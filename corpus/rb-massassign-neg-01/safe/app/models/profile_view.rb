class ProfileView
  SETTINGS = %i[theme density locale].freeze
  DEFAULTS = { theme: "system", density: "comfortable", locale: "en" }.freeze

  def initialize(settings)
    @settings = settings.to_h.symbolize_keys.slice(*SETTINGS)
  end

  def to_h
    DEFAULTS.merge(@settings)
  end
end
