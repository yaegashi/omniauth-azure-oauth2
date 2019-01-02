require 'omniauth/strategies/oauth2'
require 'jwt'

module OmniAuth
  module Strategies
    class AzureOauth2 < OmniAuth::Strategies::OAuth2
      BASE_AZURE_URL = 'https://login.microsoftonline.com'

      option :name, 'azure_oauth2'

      option :tenant_provider, nil

      # AD resource identifier
      option :resource, '00000002-0000-0000-c000-000000000000'

      # populate extra.member_groups using AAD Graph
      option :member_groups, false

      # tenant_provider must return client_id, client_secret and optionally tenant_id and base_azure_url
      args [:tenant_provider]

      def client
        if options.tenant_provider
          provider = options.tenant_provider.new(self)
        else
          provider = options  # if pass has to config, get mapped right on to options
        end

        options.client_id = provider.client_id
        options.client_secret = provider.client_secret
        options.tenant_id =
          provider.respond_to?(:tenant_id) ? provider.tenant_id : 'common'
        options.base_azure_url =
          provider.respond_to?(:base_azure_url) ? provider.base_azure_url : BASE_AZURE_URL

        options.authorize_params = provider.authorize_params if provider.respond_to?(:authorize_params)
        options.authorize_params.domain_hint = provider.domain_hint if provider.respond_to?(:domain_hint) && provider.domain_hint
        options.authorize_params.prompt = request.params['prompt'] if request.params['prompt']
        options.client_options.authorize_url = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/authorize"
        options.client_options.token_url = "#{options.base_azure_url}/#{options.tenant_id}/oauth2/token"
        super
      end

      uid {
        raw_info['sub']
      }

      info do
        {
          name: raw_info['name'],
          nickname: raw_info['unique_name'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          email: raw_info['email'] || raw_info['upn'],
          oid: raw_info['oid'],
          tid: raw_info['tid']
        }
      end

      extra do
        hash = { raw_info: raw_info }
        hash[:member_groups] = member_groups if options.member_groups
        hash
      end

      def token_params
        azure_resource = request.env['omniauth.params'] && request.env['omniauth.params']['azure_resource']
        super.merge(resource: azure_resource || options.resource)
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def raw_info
        # it's all here in JWT http://msdn.microsoft.com/en-us/library/azure/dn195587.aspx
        @raw_info ||= ::JWT.decode(access_token.token, nil, false).first
      end

      def member_groups
        # https://msdn.microsoft.com/en-us/library/azure/ad/graph/api/functions-and-actions#getMemberGroups
        # client credentials: directory read permission must be granted to the application by admin
        @member_groups ||=
          begin
            token = client.client_credentials.get_token(resource: 'https://graph.windows.net')
            url = "https://graph.windows.net/myorganization/users/#{raw_info['oid']}/getMemberGroups?api-version=1.6"
            body = { securityEnabledOnly: true }.to_json
            headers = { 'Content-Type' => 'application/json' }
            res = token.post(url, body: body, headers: headers).parsed
            res['value'] || []
          rescue ::OAuth2::Error, CallbackError => e
            fail!(:invalid_client_credentials, e)
          end
      end

    end
  end
end
