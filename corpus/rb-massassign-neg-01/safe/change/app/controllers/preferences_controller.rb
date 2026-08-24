class PreferencesController < ApplicationController
  def update
    session[:profile_view] = ProfileView.new(view_params).to_h
    redirect_to preferences_path
  end

  private

  def view_params
    ActionController::Parameters.new(
      theme: params[:theme],
      density: params[:density],
      locale: params[:locale]
    ).permit!
  end
end
