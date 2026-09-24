// このファイルは LiteLDev/LeviLaunchroid 公式サンプル
// (examples/full-cpp-mod/src/FullCppMod.cpp) を土台に、
// デモ用の複数HUDボタンを外して最小構成にしたものです。
// ワールド内のブロック状態(信号強度など)を読む処理はまだ入っていません(TODO)。

#include "RedstoneTweaksConfig.hpp"

#include <mutex>
#include <optional>
#include <string_view>

#include <pl/Mod.hpp>
#include <pl/ModMenu.hpp>

namespace {

using redstonetweaks::RedstoneTweaksConfig;

constexpr const char *kModuleId = "redstone_tweaks_mod.info";
constexpr const char *kEnabledKey = "enabled";

bool matchesModule(std::string_view moduleId) { return moduleId == kModuleId; }

bool parseBool(std::string_view value, bool fallback) {
  if (value == "true" || value == "1" || value == "on" || value == "enabled") {
    return true;
  }
  if (value == "false" || value == "0" || value == "off" ||
      value == "disabled") {
    return false;
  }
  return fallback;
}

std::string boolToMenuValue(bool value) { return value ? "true" : "false"; }

class RedstoneTweaksMod {
public:
  static RedstoneTweaksMod &instance() {
    static RedstoneTweaksMod mod;
    return mod;
  }

  RedstoneTweaksMod() : mSelf(*ll::mod::NativeMod::current()) {}

  [[nodiscard]] ll::mod::NativeMod &getSelf() const { return mSelf; }

  bool load() {
    auto &self = getSelf();
    std::lock_guard lock(mConfigMutex);
    mConfigFile.emplace();
    if (!mConfigFile->load()) {
      self.getLogger().error("Failed to load config");
      mConfigFile.reset();
      return false;
    }
    self.getLogger().info("Loaded config from {}",
                           mConfigFile->configPath().string());
    return true;
  }

  bool enable() {
    auto &self = getSelf();
    const bool enabled = snapshotConfig().enabled;

    const bool moduleRegistered =
        pl::modmenu::ModuleBuilder(kModuleId, "Redstone Tweaks Info")
            .modId(self.getId())
            .description(
                "Redstone Tweaks (Bedrock port). World overlay features are "
                "not implemented yet.")
            .defaultEnabled(true)
            .onToggle(onModuleToggle)
            .config(kEnabledKey, "Enabled", pl::modmenu::ConfigType::Toggle,
                    boolToMenuValue(enabled))
            .onConfigChanged(onConfigChanged)
            .registerModule();

    if (moduleRegistered) {
      self.getLogger().info("Registered Mod Menu module {}", kModuleId);
    } else {
      self.getLogger().error("Failed to register Mod Menu module {}",
                              kModuleId);
    }
    return moduleRegistered;
  }

  bool disable() {
    unregisterModule();
    getSelf().getLogger().info("Disabled");
    return true;
  }

  bool unload() {
    unregisterModule();
    std::lock_guard lock(mConfigMutex);
    mConfigFile.reset();
    getSelf().getLogger().info("Unloaded");
    return true;
  }

private:
  ll::mod::NativeMod &mSelf;
  std::mutex mConfigMutex;
  std::optional<pl::config::ConfigFile<RedstoneTweaksConfig>> mConfigFile;

  RedstoneTweaksConfig snapshotConfig() {
    std::lock_guard lock(mConfigMutex);
    if (!mConfigFile) {
      return RedstoneTweaksConfig{};
    }
    return mConfigFile->value();
  }

  static void onModuleToggle(std::string_view moduleId, bool enabled) {
    instance().getSelf().getLogger().info("Module {} {}", moduleId,
                                          enabled ? "enabled" : "disabled");
  }

  static void onConfigChanged(std::string_view moduleId,
                               std::string_view key, std::string_view value) {
    instance().handleConfigChanged(moduleId, key, value);
  }

  void handleConfigChanged(std::string_view moduleId, std::string_view key,
                            std::string_view value) {
    if (!matchesModule(moduleId) || key.empty()) {
      return;
    }
    std::lock_guard lock(mConfigMutex);
    if (!mConfigFile) {
      return;
    }
    auto &config = mConfigFile->value();
    if (key == kEnabledKey) {
      config.enabled = parseBool(value, config.enabled);
    } else {
      return;
    }
    if (mConfigFile->save()) {
      getSelf().getLogger().info("Persisted config after {}", key);
    } else {
      getSelf().getLogger().warn("Failed to persist config after {}", key);
    }
  }

  void unregisterModule() { pl::modmenu::unregisterModule(kModuleId); }
};

} // namespace

PL_REGISTER_MOD(RedstoneTweaksMod, RedstoneTweaksMod::instance())
