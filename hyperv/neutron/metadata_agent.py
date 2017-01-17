# Copyright 2017 Cloudbase Solutions SRL
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import hashlib
import hmac
import sys
import uuid

import httplib2
from neutron.agent.common import config as agent_conf
from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import topics
from neutron import context
from neutron import wsgi
from neutron_lib import constants
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall
from oslo_utils import encodeutils
import six
import six.moves.urllib.parse as urlparse
import webob

from hyperv.common import i18n
from hyperv.neutron import neutron_client

CONF = cfg.CONF
CONF.import_group('AGENT', 'hyperv.neutron.config')
CONF.import_group('metadata', 'hyperv.neutron.config')
LOG = logging.getLogger(__name__)


class _MetadataProxyHandler(object):

    def __init__(self, conf):
        self._config = conf
        self._context = context.get_admin_context_without_session()
        self._allow_insecure = self._config.metadata.nova_metadata_insecure
        self._nova_url = '%s:%s' % (self._config.metadata.nova_metadata_ip,
                                    self._config.metadata.nova_metadata_port)
        self._neutron_client = neutron_client.NeutronAPIClient()

    @webob.dec.wsgify(RequestClass=webob.Request)
    def __call__(self, req):
        try:
            return self._proxy_request(req)
        except Exception:
            LOG.exception(i18n._LE("Unexpected error."))
            msg = i18n._('An unknown error has occurred. '
                         'Please try your request again.')
            explanation = six.text_type(msg)
            return webob.exc.HTTPInternalServerError(explanation=explanation)

    @staticmethod
    def _check_uuid(hnv_instance_id):
        """Check if the received value is a valid UUID."""
        try:
            uuid.UUID(hnv_instance_id)
        except (ValueError, TypeError):
            return False
        return True

    def _extract_instance_id(self, value):
        """Obtain the HNV instance id from the received value."""
        hnv_instance_id = value.split(" ")[0]
        hnv_instance_id = hnv_instance_id.split("/")[-1].strip()
        if self._check_uuid(hnv_instance_id):
            return hnv_instance_id

    def _get_hnv_instance_id(self, request):
        """Get extra information from the current request."""
        for header in request.headers:
            hnv_instance_id = self._extract_instance_id(header)
            if hnv_instance_id:
                LOG.debug("The instance id was found in headers prefix.")
                return hnv_instance_id

        hnv_instance_id = self._extract_instance_id(request.body)
        if self._check_uuid(hnv_instance_id):
            LOG.debug("The instance id was found in request body.")
            return hnv_instance_id

        hnv_instance_id = self._extract_instance_id(request.path)
        if hnv_instance_id:
            LOG.debug("The instance id was found in request path.")
            return hnv_instance_id

        LOG.debug("Failed to get the instance id from the request.")
        return None

    def _get_instance_id(self, hnv_instance_id):
        tenant_id = None
        instance_id = None

        ports = self._neutron_client.get_network_ports()
        for port in ports:
            profile_id = port["binding:vif_details"].get("port_profile_id")
            if profile_id and profile_id == hnv_instance_id:
                tenant_id = port["tenant_id"]
                instance_id = port["device_id"]
                break
        else:
            LOG.debug("Failed to get the port information.")

        return tenant_id, instance_id

    def _sign_instance_id(self, instance_id):
        secret = self._config.metadata.proxy_shared_secret
        secret = encodeutils.to_utf8(secret)
        instance_id = encodeutils.to_utf8(instance_id)
        return hmac.new(secret, instance_id, hashlib.sha256).hexdigest()

    def _get_headers(self, hnv_instance_id, request):
        tenant_id, instance_id = self._get_instance_id(hnv_instance_id)
        if not all((tenant_id, instance_id)):
            return None
        signature = self._sign_instance_id(instance_id)

        headers = {}
        for header in request.headers:
            value = request.headers[header]
            if " " in header:
                headers[header.split(" ")[-1]] = value
            else:
                headers[header] = value

        headers.update({
            'X-Instance-ID': instance_id,
            'X-Tenant-ID': tenant_id,
            'X-Instance-ID-Signature': signature,
        })
        return headers

    def _proxy_request(self, request):
        LOG.debug("Request: %s", request)

        hnv_instance_id = self._get_hnv_instance_id(request)
        if not hnv_instance_id:
            return webob.exc.HTTPNotFound()

        headers = self._get_headers(hnv_instance_id, request)
        if not headers:
            return webob.exc.HTTPNotFound()

        LOG.debug("Trying to proxy the request.")
        metadata = self._config.metadata

        http_request = httplib2.Http(
            ca_certs=metadata.auth_ca_cert,
            disable_ssl_certificate_validation=self._allow_insecure
        )
        if metadata.nova_client_cert and metadata.nova_client_priv_key:
            http_request.add_certificate(
                key=metadata.nova_client_priv_key,
                cert=metadata.nova_client_cert,
                domain=self._nova_url)

        url = urlparse.urlunsplit((
            metadata.nova_metadata_protocol, self._nova_url,
            request.path_info, request.query_string, ''))

        response, content = http_request.request(
            url.replace(hnv_instance_id, ""),
            method=request.method, headers=headers,
            body=request.body)

        LOG.debug("Response [%s]: %s", response.status, content)
        if response.status == 200:
            request.response.content_type = response['content-type']
            request.response.body = content
            return request.response
        elif response.status == 403:
            LOG.warning(i18n._LW(
                'The remote metadata server responded with Forbidden. This '
                'response usually occurs when shared secrets do not match.'
            ))
            return webob.exc.HTTPForbidden()
        elif response.status == 400:
            return webob.exc.HTTPBadRequest()
        elif response.status == 404:
            return webob.exc.HTTPNotFound()
        elif response.status == 409:
            return webob.exc.HTTPConflict()
        elif response.status == 500:
            message = i18n._(
                'Remote metadata server experienced an internal server error.'
            )
            LOG.warning(message)
            return webob.exc.HTTPInternalServerError(explanation=message)
        else:
            raise Exception(i18n._('Unexpected response code: %s') %
                            response.status)


class MetadataProxy(object):

    def __init__(self, conf):
        self._config = conf
        self._context = None
        self._state_rpc = None
        self._agent_state = None
        self._heartbeat = None

    def _get_configuration(self):
        metadata = self._config.metadata
        return {
            'nova_metadata_ip': metadata.nova_metadata_ip,
            'nova_metadata_port': metadata.nova_metadata_port,
            'log_agent_heartbeats': self._config.AGENT.log_agent_heartbeats,
        }

    def _init_state_reporting(self):
        self._context = context.get_admin_context_without_session()
        self._state_rpc = agent_rpc.PluginReportStateAPI(topics.REPORTS)
        self._agent_state = {
            'binary': 'neutron-hnv-metadata-proxy',
            'host': self._config.metadata.host,
            'topic': 'N/A',
            'configurations': self._get_configuration(),
            'start_flag': True,
            'agent_type': constants.AGENT_TYPE_METADATA
        }
        report_interval = self._config.AGENT.report_interval
        if report_interval:
            self._heartbeat = loopingcall.FixedIntervalLoopingCall(
                self._report_state)
            self._heartbeat.start(interval=report_interval)

    def _report_state(self):
        try:
            self._state_rpc.report_state(
                self._context,
                self._agent_state,
                use_call=self._agent_state.get('start_flag'))
        except AttributeError:
            # This means the server does not support report_state
            LOG.warning(i18n._LW(
                'Neutron server does not support state report.'
                ' State report for this agent will be disabled.'))
            self._heartbeat.stop()
            return
        except Exception:
            LOG.exception(i18n._LE("Failed reporting state!"))
            return
        self._agent_state.pop('start_flag', None)

    def run(self):
        """Start the neutron-hnv-metadata-proxy agent."""
        server = wsgi.Server(
            name="neutron-hnv-metadata-proxy",
            num_threads=self._config.AGENT.worker_count,
        )
        server.start(
            application=_MetadataProxyHandler(self._config),
            port=self._config.metadata.bind_port,
            host=self._config.metadata.bind_host,
        )
        self._init_state_reporting()
        server.wait()


def main():
    """The entry point for neutron-hnv-metadata-proxy."""
    agent_conf.register_agent_state_opts_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    agent_conf.setup_logging()
    proxy = MetadataProxy(cfg.CONF)
    proxy.run()
