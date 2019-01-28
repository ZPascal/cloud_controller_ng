require 'presenters/v3/app_environment_variables_presenter'
require 'presenters/v3/base_presenter'

module VCAP::CloudController
  module Presenters
    module V3
      class RevisionEnvironmentVariablesPresenter
        attr_reader :revision

        def initialize(revision)
          @revision = revision
        end

        def to_hash
          result = {
            var: {},
            links: build_links
          }

          env_vars&.each do |key, value|
            result[:var][key.to_sym] = value
          end

          result
        end

        private

        def env_vars
          revision&.environment_variables
        end

        def build_links
          url_builder = VCAP::CloudController::Presenters::ApiUrlBuilder.new

          {
            self: { href: url_builder.build_url(path: "/v3/apps/#{revision.app.guid}/revisions/#{revision.guid}/environment_variables") },
            revision: { href: url_builder.build_url(path: "/v3/apps/#{revision.app.guid}/revisions/#{revision.guid}") },
            app:  { href: url_builder.build_url(path: "/v3/apps/#{revision.app.guid}") }
          }
        end
      end
    end
  end
end
