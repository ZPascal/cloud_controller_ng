module VCAP::CloudController
  module SecurityContext
    def self.clear
      Thread.current[:vcap_user] = nil
      Thread.current[:vcap_token] = nil
      Thread.current[:vcap_auth_token] = nil
    end

    def self.set(user, token=nil, auth_token=nil)
      Thread.current[:vcap_user] = user
      Thread.current[:vcap_token] = token
      Thread.current[:vcap_auth_token] = auth_token
    end

    def self.current_user
      Thread.current[:vcap_user]
    end

    def self.current_user_guid
      current_user.guid if current_user
    end

    def self.admin?
      roles.admin?
    end

    def self.admin_read_only?
      roles.admin_read_only?
    end

    def self.v2_rate_limit_exempted?
      roles.v2_rate_limit_exempted?
    end

    def self.global_auditor?
      roles.global_auditor?
    end

    def self.roles
      VCAP::CloudController::Roles.new(token)
    end

    def self.token
      Thread.current[:vcap_token]
    end

    def self.auth_token
      Thread.current[:vcap_auth_token]
    end

    def self.missing_token?
      token.nil?
    end

    def self.valid_token?
      token && token != :invalid_token
    end

    def self.invalid_token?
      !valid_token?
    end

    def self.scopes
      valid_token? && token['scope'] || []
    end

    def self.current_user_email
      token['email'] if valid_token?
    end

    def self.current_user_name
      token['user_name'] if valid_token?
    end

    def self.current_user_has_email?(email)
      current_user_email && current_user_email.downcase == email.downcase
    end

    def self.issuer
      return token['iss'] if valid_token?

      ''
    end
  end
end
