class UsersController < ApplicationController
  # codelens-expect: CSRF_DISABLED
  skip_before_action :verify_authenticity_token, only: [:create]

  def index
    # codelens-expect: SQL_INJECTION
    @users = User.where("name = '#{params[:name]}'")
    @safe = User.where("name = ?", params[:name])
    @also = User.where(name: params[:name])
  end

  def ping
    # codelens-expect: COMMAND_INJECTION
    system("ping -c 1 #{params[:host]}")
    system("ping", "-c", "1", params[:host])
  end

  def restore
    # codelens-expect: INSECURE_DESERIALIZATION
    Marshal.load(Base64.decode64(params[:state]))
  end

  def calc
    # codelens-expect: CODE_INJECTION
    eval(params[:expr])
  end

  def bio
    # codelens-expect: UNSAFE_HTML
    "<b>#{params[:bio]}</b>".html_safe
  end

  def fetch
    http = Net::HTTP.new("example.com", 443)
    # codelens-expect: TLS_VERIFY_DISABLED
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  end
end
