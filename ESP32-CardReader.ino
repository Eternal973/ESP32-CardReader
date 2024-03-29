#include "Aime_Reader.h"

void (*ReaderMain)();

void setup() {
  pinMode(SW1_MODE, INPUT_PULLUP);  // Switch mode
  pinMode(SW3_CARD, INPUT_PULLUP);  // Hardcode mifare
  pinMode(SW4_FW, INPUT_PULLUP);    // (Aime) Baudrate & fw/hw | (Spice) 1P 2P
  FastLED.addLeds<WS2812B, LED_PIN, GRB>(leds, 8);
  FastLED.setBrightness(20);  // LED brightness
  FastLED.showColor(0);

  nfc.begin();
  while (!nfc.getFirmwareVersion()) {
    FastLED.showColor(0xFF0000);
    delay(500);
    FastLED.showColor(0);
    delay(500);
  }
  nfc.setPassiveActivationRetries(0x10);
  nfc.SAMConfig();

  // mode select
  ReaderMode = !digitalRead(SW1_MODE);
  FWSW = !digitalRead(SW4_FW);
  if (ReaderMode) {  // BEMANI mode
    SerialDevice.begin(115200);
    FastLED.showColor(CRGB::Yellow);
    ReaderMain = SpiceToolsReader;
  } else {  // Aime mode
    SerialDevice.begin(FWSW ? 38400 : 115200);
    FastLED.showColor(FWSW ? CRGB::Green : CRGB::Blue);
    ReaderMain = AimeCardReader;
  }

  memset(req.bytes, 0, sizeof(req.bytes));
  memset(res.bytes, 0, sizeof(res.bytes));

  ConnectTime = millis();
  ConnectStatus = true;
}


void loop() {
  ReaderMain();

  if (ConnectStatus) {
    if ((millis() - ConnectTime) > SleepDelay) {
      ConnectStatus = false;
    }
  } else {
    if ((millis() - ConnectTime) < SleepDelay) {
      ConnectStatus = true;
    }
  }
}


void SpiceToolsReader() {  // Spice mode
  uint16_t SystemCode;
  char card_id[17];
  if (nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, res.mifare_uid, &res.id_len)
      && nfc.mifareclassic_AuthenticateBlock(res.mifare_uid, res.id_len, 1, 0, DefaultKey)
      && nfc.mifareclassic_ReadDataBlock(1, res.block)) {
    sprintf(card_id, "%02X%02X%02X%02X%02X%02X%02X%02X",
            res.block[0], res.block[1], res.block[2], res.block[3],
            res.block[4], res.block[5], res.block[6], res.block[7]);

  } else if (nfc.felica_Polling(0xFFFF, 0x00, res.IDm, res.PMm, &SystemCode, 200) == 1) {
    sprintf(card_id, "%02X%02X%02X%02X%02X%02X%02X%02X",
            res.IDm[0], res.IDm[1], res.IDm[2], res.IDm[3],
            res.IDm[4], res.IDm[5], res.IDm[6], res.IDm[7]);
  } else {
    return;
  }
  spiceapi::InfoAvs avs_info{};
  if (spiceapi::info_avs(CON, avs_info)) {
    FWSW = !digitalRead(SW4_FW);
    spiceapi::card_insert(CON, FWSW, card_id);
    for (int i = 0; i < 8; i++) {
      leds[i] = CRGB::Red;
      leds[7 - i] = CRGB::Blue;
      FastLED.delay(50);
      leds[i] = CRGB::Black;
      leds[7 - i] = CRGB::Black;
    }
    FastLED.show();
  }
  ConnectTime = millis();
}


void AimeCardReader() {  // Aime mode
  switch (packet_read()) {
    case 0:
      return;
    case CMD_TO_NORMAL_MODE:
      sys_to_normal_mode();
      break;
    case CMD_GET_FW_VERSION:
      sys_get_fw_version();
      break;
    case CMD_GET_HW_VERSION:
      sys_get_hw_version();
      break;
    // Card read
    case CMD_START_POLLING:
      nfc_start_polling();
      break;
    case CMD_STOP_POLLING:
      nfc_stop_polling();
      break;
    case CMD_CARD_DETECT:
      nfc_card_detect();
      break;
    // MIFARE
    case CMD_MIFARE_KEY_SET_A:
      memcpy(KeyA, req.key, 6);
      res_init();
      break;
    case CMD_MIFARE_KEY_SET_B:
      res_init();
      memcpy(KeyB, req.key, 6);
      break;
    case CMD_MIFARE_AUTHORIZE_A:
      nfc_mifare_authorize_a();
      break;
    case CMD_MIFARE_AUTHORIZE_B:
      nfc_mifare_authorize_b();
      break;
    case CMD_MIFARE_READ:
      nfc_mifare_read();
      break;
    // FeliCa
    case CMD_FELICA_THROUGH:
      nfc_felica_through();
      break;
    // LED
    case CMD_EXT_BOARD_LED_RGB:
      FastLED.showColor(CRGB(req.color_payload[0], req.color_payload[1], req.color_payload[2]));
      break;
    case CMD_EXT_BOARD_INFO:
      sys_get_led_info();
      break;
    case CMD_EXT_BOARD_LED_RGB_UNKNOWN:
      break;
    default:
      res_init();
  }
  ConnectTime = millis();
  packet_write();
}
