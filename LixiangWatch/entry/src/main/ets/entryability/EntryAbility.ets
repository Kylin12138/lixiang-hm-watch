import { AbilityConstant, ConfigurationConstant, UIAbility, Want } from '@kit.AbilityKit';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { window } from '@kit.ArkUI';

const DOMAIN: number = 0x0001;
const TAG: string = 'LixiangWatch';

export default class EntryAbility extends UIAbility {
  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
    this.context.getApplicationContext().setColorMode(ConfigurationConstant.ColorMode.COLOR_MODE_DARK);
    hilog.info(DOMAIN, TAG, 'Ability onCreate');
  }

  onDestroy(): void {
    hilog.info(DOMAIN, TAG, 'Ability onDestroy');
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
    hilog.info(DOMAIN, TAG, 'onWindowStageCreate');

    // ★ P2-5：屏幕常亮改为【按需】。
    //   以前这里无条件 setWindowKeepScreenOn(true) —— 手表 OLED 长期亮屏
    //   既费电又会烧屏。真正需要常亮的只有登录那 20~30 秒（bcrypt 计算期间
    //   用户必须看得见进度，否则会以为卡死而强退），
    //   现在由 Index.setScreenOn() 在登录开始时打开、结束时关闭。
    try {
      windowStage.getMainWindowSync().setWindowKeepScreenOn(false);
    } catch (e) {
      const err = e as Error;
      hilog.warn(DOMAIN, TAG, 'setWindowKeepScreenOn 失败: %{public}s', err.message);
    }

    windowStage.loadContent('pages/Index', (err) => {
      if (err.code) {
        hilog.error(DOMAIN, TAG, 'Failed to load the content. Cause: %{public}s', JSON.stringify(err));
        return;
      }
      hilog.info(DOMAIN, TAG, 'Succeeded in loading the content.');
    });
  }

  onWindowStageDestroy(): void {
    hilog.info(DOMAIN, TAG, 'onWindowStageDestroy');
  }

  onForeground(): void {
    hilog.info(DOMAIN, TAG, 'Ability onForeground');
  }

  onBackground(): void {
    hilog.info(DOMAIN, TAG, 'Ability onBackground');
  }
}
