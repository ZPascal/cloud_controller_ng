module VCAP::CloudController
  class SyslogDrainUrlsInternalController < RestController::BaseController
    # Endpoint uses mutual tls for auth, handled by nginx
    allow_unauthenticated_access

    get '/internal/v4/syslog_drain_urls', :list

    def list
      prepare_aggregate_function
      guid_to_drain_maps = AppModel.
                           join(ServiceBinding.table_name, app_guid: :guid).
                           join(Space.table_name, guid: :apps__space_guid).
                           join(Organization.table_name, id: :spaces__organization_id).
                           where(Sequel.lit('syslog_drain_url IS NOT NULL')).
                           where(Sequel.lit("syslog_drain_url != ''")).
                           group(
                             "#{AppModel.table_name}__guid".to_sym,
                             "#{AppModel.table_name}__name".to_sym,
                             "#{Space.table_name}__name".to_sym,
                             "#{Organization.table_name}__name".to_sym
                           ).
                           select(
                             "#{AppModel.table_name}__guid".to_sym,
                             "#{AppModel.table_name}__name".to_sym,
                             aggregate_function("#{ServiceBinding.table_name}__syslog_drain_url".to_sym).as(:syslog_drain_urls)
                           ).
                           select_append("#{Space.table_name}__name___space_name".to_sym).
                           select_append("#{Organization.table_name}__name___organization_name".to_sym).
                           order(:guid).
                           limit(batch_size).
                           offset(last_id).
                           all

      next_page_token = nil
      drain_urls = {}

      guid_to_drain_maps.each do |guid_and_drains|
        drain_urls[guid_and_drains[:guid]] = {
          drains: guid_and_drains[:syslog_drain_urls].split(','),
          hostname: hostname_from_app_name(guid_and_drains[:organization_name], guid_and_drains[:space_name], guid_and_drains[:name])
        }
      end

      next_page_token = last_id + batch_size unless guid_to_drain_maps.empty?

      [HTTP::OK, MultiJson.dump({ results: drain_urls, next_id: next_page_token }, pretty: true)]
    end

    get '/internal/v4/get_client_certs', :client_certs

    def client_certs
      service_bindings = ServiceBinding.
                         exclude(syslog_drain_url: nil).
                         exclude(syslog_drain_url: '').
                         where(Sequel.lit('updated_at > ?', updated_at_param)).
                         select(:updated_at, :credentials, :syslog_drain_url, :app_guid, :salt, :encryption_key_label, :encryption_iterations).all

      outcome = {}
      service_bindings.select { |sb|
        creds = sb.credentials
        creds.include?('cert') &&
        !creds.fetch('cert', '').empty? &&
        creds.include?('key') &&
        !creds.fetch('key', '').empty?
      }.map { |sb|
        creds = sb.credentials
        cert = creds.fetch('cert')
        key = creds.fetch('key')
        {
          app_ids: [sb.app_guid],
          credentials: {
            cert: cert,
            private_key: key
          },
          credentials_md5: Digest::MD5.hexdigest(cert + key)
        }
      }.each { |uc|
        if outcome[uc[:credentials_md5]].nil?
          outcome[uc[:credentials_md5]] = {
            app_ids: uc[:app_ids],
            credentials: uc[:credentials]
          }
        else
          outcome[uc[:credentials_md5]] = {
            app_ids: outcome[uc[:credentials_md5]][:app_ids].concat(uc[:app_ids]),
            credentials: uc[:credentials]
          }
        end
      }

      [HTTP::OK, MultiJson.dump({ certificates: outcome.values, updated_at: DateTime.now.iso8601 }, pretty: true)]
    end

    private

    def hostname_from_app_name(*names)
      names.map { |name|
        name.gsub(/\s+/, '-').gsub(/[^-a-zA-Z0-9]+/, '').sub(/-+$/, '')[0..62]
      }.join('.')
    end

    def aggregate_function(column)
      if AppModel.db.database_type == :postgres
        Sequel.function(:string_agg, column, ',')
      elsif AppModel.db.database_type == :mysql
        Sequel.function(:group_concat, column)
      else
        raise 'Unknown database type'
      end
    end

    def prepare_aggregate_function
      if AppModel.db.database_type == :mysql
        AppModel.db.run('SET SESSION group_concat_max_len = 1000000000')
      end
    end

    def last_id
      Integer(params.fetch('next_id', 0))
    end

    def batch_size
      Integer(params.fetch('batch_size', 50))
    end

    def updated_at_param
      params.fetch('updated_at', (Date.today - 1)).to_datetime.iso8601
    end
  end
end
