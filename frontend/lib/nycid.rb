module NYCID
  class NYCIDWebServices
    # Validate a user's email address
    EMAIL_VALIDATION_ENDPOINT = '/account/validateEmail.htm'.freeze
    # Check the validation status of the user's email address
    EMAIL_VALIDATION_STATUS_ENDPOINT = '/account/api/isEmailValidated.htm'.freeze
    # Search for a user by their guid or email addresss
    USER_SEARCH_ENDPOINT = '/account/api/user.htm'.freeze
    # Search for multiple users by their guids or their "Start Date"
    USERS_SEARCH_ENDPOINT = '/account/api/getUsers.htm'.freeze
    # Default HTTP Verb for API
    DEFAULT_METHOD = 'GET'.freeze

    def initialize(
        service_account_username: AppConfig[:nyc_id_web_services_username],
        service_account_password: AppConfig[:nyc_id_web_services_password],
        api_uri: AppConfig[:nyc_id_web_services_url]
    )
      @service_account_username = service_account_username
      @service_account_password = service_account_password
      @api_uri = api_uri
      @acs_url = AppConfig[:saml_acs]
    end

    # Checks the users email validation status using NYC.ID Web Services.
    #
    # Params:
    # * +:guid+ - Unique identifier for the user from NYC.ID
    #
    # Returns:
    # Boolean value of user's email validation status.
    def check_email_validation_status(guid)
      params = { guid: guid }
      response = nycid_web_services_request(
          EMAIL_VALIDATION_STATUS_ENDPOINT,
          params,
          method: DEFAULT_METHOD
      )
      response['validated']
    end

    # Validates the users email address using NYC.ID Web Services.
    #
    # Params:
    # * +:email_address+ - User's email address.
    #
    # Returns:
    # String of URL to request another validation email.
    def validate_email(email_address)
      if email_address.nil?
        raise ArgumentError, 'You must provide an email_address'
      end

      "#{@api_uri}#{EMAIL_VALIDATION_ENDPOINT}?emailAddress=#{email_address}&target=#{@acs_url}"
    end

    # Retrieves a JSON-formatted user from the NYC.ID Web Services API.
    #
    # Params:
    # * +:guid+ - User's unique identifier.
    #
    # Returns:
    # JSON-formatted user as specified by NYC.ID (http://nyc4d.nycnet/nycid/search.shtml#json-formatted-users).
    def search_user(guid)
      nycid_web_services_request(
          USER_SEARCH_ENDPOINT,
          { guid: guid },
          method: DEFAULT_METHOD
      )
    end

    private

    # Query the NYC.ID Web Services API.
    #
    # Params:
    # * +:endpoint+ - Services endpoint being targeted.
    # * +:params+ - Query parameters for the endpoint.
    # * +:method+ - HTTP Verb being used in the API call. Defaults to "GET".
    #
    # Returns:
    # HTTP Response from NYC.ID Web Services API Endpoint.
    def nycid_web_services_request(endpoint, params, method: DEFAULT_METHOD)
      Rails.logger.info "NYC Web Services Request: #{method} #{endpoint}"
      Rails.logger.info "#{params}"
      params[:userName] = @service_account_username
      signature = generate_nycid_signature(endpoint, params, @service_account_password, method: method)
      params[:signature] = signature

      url = @api_uri + "#{endpoint}"
      Rails.logger.info "#{url}"
      response = HTTParty.get(url, query: params)
      if response.code != 200
        Rails.logger.error JSON.pretty_generate(response.parsed_response)
      end

      response.parsed_response
    end

    # Generate a signature for a request to the NYC.ID Web Services API.
    #
    # Params:
    # * +:url_path+ - URL Path being accessed (without domain). See constants for valid values.
    # * +:query_string+ - Query String in a hash of (key, value) pairs.
    # * +:nycid_web_services_password+ - Password used to authenticate with NYC.ID Web Services.
    # * +:method+ - HTTP Verb being used in the API call. Defaults to "GET".
    #
    # Returns:
    # HMAC-SHA256 Signature for NYC.ID Web Services request.
    def generate_nycid_signature(url_path, query_string, signing_key, method: DEFAULT_METHOD)
      # endpoint must begin with a forward slash
      url_path = "/#{url_path}" if url_path.first != '/'

      # Sort the query string by keys
      parameter_values = Hash[query_string.sort_by { |key, val| key.to_s }]

      # Signature contains only the values of the sorted query string joined with no separator
      signature_parameter_values = parameter_values.map { |key, val| "#{val}" }.join

      value_to_sign = "#{method}#{url_path}#{signature_parameter_values}"

      OpenSSL::HMAC.hexdigest('sha256', signing_key, value_to_sign)
    end
  end
end