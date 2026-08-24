class PreferencesController < ApplicationController
  def update
    current_user.update!(view_params)
    redirect_to preferences_path
  end

  private

  def view_params
    params.require(:user).permit!.reverse_merge(
      theme: ProfileView::DEFAULTS[:theme],
      density: ProfileView::DEFAULTS[:density],
      locale: ProfileView::DEFAULTS[:locale]
    )
  end
end
