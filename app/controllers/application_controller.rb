class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_action :authenticate_user
  
  private
  def logged_in?
    !!session[:token]
  end

  def authenticate_user
    if !logged_in?
      client_id = ENV['FOURSQUARE_CLIENT_ID']
      client_secret = ENV['FOURSQUARE_CLIENT_SECRET']
      redirect_uri = CGI.escape("http://localhost:3000/auth")
      redirect_to "https://foursquare.com/oauth2/authenticate?client_id=#{client_id}&response_type=code&redirect_uri=#{redirect_uri}"
    end
  end
end
