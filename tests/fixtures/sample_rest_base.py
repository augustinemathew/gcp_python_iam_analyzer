# Extracted from google/cloud/kms_v1/services/key_management_service/transports/rest_base.py
# Trimmed to 7 representative methods for testing.
# Copyright 2025 Google LLC — Apache License 2.0

class KeyManagementServiceTransport:
    pass


class _BaseKeyManagementServiceRestTransport(KeyManagementServiceTransport):

    @staticmethod
    def _get_http_options():
        return [{}]

    class _BaseCreateKeyRing:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "post",
                    "uri": "/v1/{parent=projects/*/locations/*}/keyRings",
                    "body": "key_ring",
                },
            ]
            return http_options

    class _BaseEncrypt:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "post",
                    "uri": "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/**}:encrypt",
                    "body": "*",
                },
            ]
            return http_options

    class _BaseDecrypt:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "post",
                    "uri": "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/*}:decrypt",
                    "body": "*",
                },
            ]
            return http_options

    class _BaseGetCryptoKey:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "get",
                    "uri": "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/*}",
                },
            ]
            return http_options

    class _BaseListCryptoKeys:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "get",
                    "uri": "/v1/{parent=projects/*/locations/*/keyRings/*}/cryptoKeys",
                },
            ]
            return http_options

    class _BaseDestroyCryptoKeyVersion:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "post",
                    "uri": "/v1/{name=projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*}:destroy",
                    "body": "*",
                },
            ]
            return http_options

    class _BaseGetIamPolicy:
        @staticmethod
        def _get_http_options():
            http_options = [
                {
                    "method": "get",
                    "uri": "/v1/{resource=projects/*/locations/*/keyRings/*}:getIamPolicy",
                },
                {
                    "method": "get",
                    "uri": "/v1/{resource=projects/*/locations/*/keyRings/*/cryptoKeys/*}:getIamPolicy",
                },
                {
                    "method": "get",
                    "uri": "/v1/{resource=projects/*/locations/*/keyRings/*/importJobs/*}:getIamPolicy",
                },
                {
                    "method": "get",
                    "uri": "/v1/{resource=projects/*/locations/*/ekmConfig}:getIamPolicy",
                },
                {
                    "method": "get",
                    "uri": "/v1/{resource=projects/*/locations/*/ekmConnections/*}:getIamPolicy",
                },
            ]
            return http_options
