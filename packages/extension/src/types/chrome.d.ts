declare namespace chrome {
  namespace action {
    function setBadgeText(details: { text: string; tabId?: number }): Promise<void>;
    function setBadgeBackgroundColor(details: { color: string; tabId?: number }): Promise<void>;
  }

  namespace alarms {
    interface Alarm {
      name: string;
      scheduledTime: number;
      periodInMinutes?: number;
    }
    function create(name: string, alarmInfo: { periodInMinutes?: number; delayInMinutes?: number }): void;
    const onAlarm: {
      addListener(callback: (alarm: Alarm) => void): void;
    };
  }

  namespace runtime {
    interface MessageSender {
      id?: string;
      url?: string;
    }
    const onMessage: {
      addListener(
        callback: (
          message: Record<string, unknown>,
          sender: MessageSender,
          sendResponse: (response?: unknown) => void,
        ) => boolean | undefined,
      ): void;
    };
  }

  namespace sidePanel {
    function open(options: { windowId: number; tabId?: number }): Promise<void>;
  }

  namespace windows {
    interface Window {
      id?: number;
    }
    function getCurrent(callback: (window: Window) => void): void;
  }
}
