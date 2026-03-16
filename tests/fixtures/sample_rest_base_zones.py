# Extracted from google/cloud/compute_v1/services/zones/transports/rest_base.py
# Copyright 2025 Google LLC — Apache License 2.0

class ZonesTransport:
    pass


class _BaseZonesRestTransport(ZonesTransport):

    class _BaseGet:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "get",
                    "uri": "/compute/v1/projects/{project}/zones/{zone}",
                },
            ]
            return http_options

    class _BaseList:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "get",
                    "uri": "/compute/v1/projects/{project}/zones",
                },
            ]
            return http_options
