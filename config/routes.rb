Rails.application.routes.draw do
  root to: 'articles#index'
  resources :articles

  devise_for :users, controllers: {
    sessions: 'users/sessions'
  }
end
