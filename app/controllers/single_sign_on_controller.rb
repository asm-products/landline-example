class SingleSignOnController < ApplicationController
  require 'addressable/uri'
  after_filter :set_access_control_headers

  def sso
    return render nothing: true, status: 401 unless sign(params[:payload]) == params[:sig]
    return render nothing: true, status: 401 unless nonce = extract_nonce
    return render nothing: true, status: 403 unless current_user = extract_user

    user = Addressable::URI.new
    user.query_values = {
      nonce: nonce,
      team: ENV["LANDLINE_TEAM"],
      id: current_user.id,
      avatar_url: gravatar_url(current_user),
      username: current_user.email,
      email: current_user.email,
      real_name: current_user.email,
      profile_url: root_url
    }

    payload = Base64.encode64(user.query)
    sig = sign(payload)
    url = "#{ENV["LANDLINE_URL"]}/sessions/sso?payload=#{URI.escape(payload)}&sig=#{sig}"

    redirect_to url
  end

  private

  def decode_payload
    payload = params[:payload]
    raw = Base64.decode64(payload)
    uri = CGI.parse(raw)
  end

  def extract_nonce
    decode_payload["nonce"][0]
  end

  def extract_user
    # NB: In a production app, this wouldn't be acceptable, as users know each
    # other's emails and so could impersonate one another. For now, I'm leaving
    # it as an exercise to the reader to implement a more secure (perhaps
    # token-based) authentication scheme.
    User.find_by(email: decode_payload["user"][0])
  end

  def gravatar_url(current_user)
    "http://www.gravatar.com/avatar/#{Digest::MD5.hexdigest(current_user.email.downcase)}"
  end

  def sign(payload)
    digest = OpenSSL::Digest.new('sha256')
    OpenSSL::HMAC.hexdigest(digest, ENV["LANDLINE_SECRET"], payload)
  end

  def set_access_control_headers
    headers['Access-Control-Allow-Origin'] = '*'
    headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE'
    headers['Access-Control-Request-Method'] = '*'
    headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept'
  end
end
