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
                             aggregate_function("#{ServiceBinding.table_name}__syslog_drain_url".to_sym).as(:syslog_drain_urls),
                             aggregate_function("#{ServiceBinding.table_name}__id".to_sym).as(:service_binding_ids)
                           ).
                           select_append("#{Space.table_name}__name___space_name".to_sym).
                           select_append("#{Organization.table_name}__name___organization_name".to_sym).
                           order(:guid).
                           limit(batch_size).
                           offset(last_id).
                           all

      next_page_token = nil
      drain_urls = {}

      # get all service binding ids
      sb_ids = Array.new
      guid_to_drain_maps.each do |guid_and_drains|
         sb_ids_str = guid_and_drains[:service_binding_ids]
         sb_ids_str_array = sb_ids_str.split(',')
         sb_ids_str_array.each { |x| sb_ids.push x }
      end

      # get all credentials of service bindings
      credentials = ServiceBinding.
                      where(id: sb_ids).
                      select(:id, :credentials, :salt, :encryption_key_label, :encryption_iterations).
                      all.
                      map{|t| [t.id.to_s, {"cert"=>(t.credentials.present? && t.credentials.has_key?("cert") ? t.credentials["cert"] : ""), "key"=> (t.credentials.present? && t.credentials.has_key?("key") ? t.credentials["key"] : "")} ]}.to_h

      guid_to_drain_maps.each do |guid_and_drains|
        drain_credentials_pairs = Array.new
        app_drain_ids = guid_and_drains[:service_binding_ids].split(',')
        app_drain_urls = guid_and_drains[:syslog_drain_urls].split(',')
        app_drain_ids.each_with_index do |id,index|
            drain_credentials = credentials[id]
            drain_credentials_pairs.push({
                drain: app_drain_urls[index],
                cert: drain_credentials["cert"],
                key: drain_credentials["key"]
            }.to_h)
        end

        drain_urls[guid_and_drains[:guid]] = {
          drains: guid_and_drains[:syslog_drain_urls].split(','),
          hostname: hostname_from_app_name(guid_and_drains[:organization_name], guid_and_drains[:space_name], guid_and_drains[:name]),
          credentials: drain_credentials_pairs
        }
      end

      next_page_token = last_id + batch_size unless guid_to_drain_maps.empty?

      [HTTP::OK, MultiJson.dump({ results: drain_urls, next_id: next_page_token }, pretty: true)]
    end

    private

    def hostname_from_app_name(*names)
      names.map { |name|
        name.gsub(/\s+/, '-').gsub(/[^-a-zA-Z0-9]+/, '').sub(/-+$/, '')[0..62]
      }.join('.')
    end

    def aggregate_function(column)
      if AppModel.db.database_type == :postgres
        Sequel.function(:string_agg, Sequel.cast(column, :text), ',')
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
  end
end
