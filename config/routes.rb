Rails.application.routes.draw do
  devise_for :users

  root 'chat#index'
  get '/sso' => 'single_sign_on#sso'
end
