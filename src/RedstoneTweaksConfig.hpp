#pragma once

#include <string_view>

#include <pl/Config.hpp>

namespace redstonetweaks {

struct RedstoneTweaksConfig {
  int version = 1;
  bool enabled = true;
  // TODO: signal-strength overlay 等、オフセットが見つかったら設定項目を足す
};

} // namespace redstonetweaks

namespace pl::config {

template <> struct Schema<redstonetweaks::RedstoneTweaksConfig> {
  static constexpr std::string_view title = "Redstone Tweaks Info";
  static constexpr std::string_view description =
      "Redstone Tweaks (Bedrock port) settings.";

  static constexpr FieldSchema field(std::string_view name) {
    if (name == "version") {
      return {"Version", "Config schema version managed by the mod.",
              std::nullopt, std::nullopt, true};
    }
    if (name == "enabled") {
      return {"Enabled", "Master on/off switch for this mod.",
              std::nullopt, std::nullopt, false};
    }
    return {};
  }
};

} // namespace pl::config
