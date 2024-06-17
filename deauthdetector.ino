#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>

// include ESP8266 Non-OS SDK functions
extern "C" {
#include "user_interface.h"
}

// ===== SETTINGS ===== //
#define LED 2              /* LED pin (2=built-in LED) */
#define LED_INVERT true    /* Invert HIGH/LOW for LED */
#define SERIAL_BAUD 115200 /* Baudrate for serial communication */
#define CH_TIME 140        /* Scan time (in ms) per channel */
#define PKT_RATE 5         /* Min. packets before it gets recognized as an attack */
#define PKT_TIME 1         /* Min. interval (CH_TIME*CH_RANGE) before it gets recognized as an attack */

const char* ssid = "Tên_Mạng_Wifi";
const char* password = "Mật_Khẩu_Mạng_Wifi";
const char* apiToken = "API_TOKEN";
const char* userToken = "USER_TOKEN";

//Pushover API endpoint
const char* pushoverApiEndpoint = "https://api.pushover.net/1/messages.json";
//Pushover root certificate (valid from 11/10/2006 to 11/10/2031)
const char* PUSHOVER_ROOT_CA = "-----BEGIN CERTIFICATE-----\n"
                               "MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQUFADBh\n"
                               "MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\n"
                               "d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBD\n"
                               "QTAeFw0wNjExMTAwMDAwMDBaFw0zMTExMTAwMDAwMDBaMGExCzAJBgNVBAYTAlVT\n"
                               "MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\n"
                               "b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IENBMIIBIjANBgkqhkiG\n"
                               "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4jvhEXLeqKTTo1eqUKKPC3eQyaKl7hLOllsB\n"
                               "CSDMAZOnTjC3U/dDxGkAV53ijSLdhwZAAIEJzs4bg7/fzTtxRuLWZscFs3YnFo97\n"
                               "nh6Vfe63SKMI2tavegw5BmV/Sl0fvBf4q77uKNd0f3p4mVmFaG5cIzJLv07A6Fpt\n"
                               "43C/dxC//AH2hdmoRBBYMql1GNXRor5H4idq9Joz+EkIYIvUX7Q6hL+hqkpMfT7P\n"
                               "T19sdl6gSzeRntwi5m3OFBqOasv+zbMUZBfHWymeMr/y7vrTC0LUq7dBMtoM1O/4\n"
                               "gdW7jVg/tRvoSSiicNoxBN33shbyTApOB6jtSj1etX+jkMOvJwIDAQABo2MwYTAO\n"
                               "BgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUA95QNVbR\n"
                               "TLtm8KPiGxvDl7I90VUwHwYDVR0jBBgwFoAUA95QNVbRTLtm8KPiGxvDl7I90VUw\n"
                               "DQYJKoZIhvcNAQEFBQADggEBAMucN6pIExIK+t1EnE9SsPTfrgT1eXkIoyQY/Esr\n"
                               "hMAtudXH/vTBH1jLuG2cenTnmCmrEbXjcKChzUyImZOMkXDiqw8cvpOp/2PV5Adg\n"
                               "06O/nVsJ8dWO41P0jmP6P6fbtGbfYmbW0W5BjfIttep3Sp+dWOIrWcBAI+0tKIJF\n"
                               "PnlUkiaY4IBIqDfv8NZ5YBberOgOzW6sRBc4L0na4UU+Krk2U886UAb3LujEV0ls\n"
                               "YSEY1QSteDwsOoBrp+uvFRTp2InBuThs4pFsiv9kuXclVzDAGySj4dzp30d8tbQk\n"
                               "CAUw7C29C79Fv1C5qfPrmAESrciIxpg0X40KPMbp1ZWVbd4=\n"
                               "-----END CERTIFICATE-----\n";

// Create a list of certificates with the server certificate
X509List cert(PUSHOVER_ROOT_CA);

// Channels to scan on (US=1-11, EU=1-13, JAP=1-14)
const short channels[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 /*,14*/ };

// ===== Runtime variables ===== //
int ch_index{ 0 };               // Current index of channel array
int packet_rate{ 0 };            // Deauth packet counter (resets with each update)
int attack_counter{ 0 };         // Attack counter
unsigned long update_time{ 0 };  // Last update time
unsigned long ch_time{ 0 };      // Last channel hop time

void connect() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");
  // Set time via NTP, as required for x.509 validation
  configTime(3 * 3600, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("Waiting for NTP time sync: ");
  time_t now = time(nullptr);
  while (now < 8 * 3600 * 2) {
    delay(100);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println("");
  struct tm timeinfo;
  gmtime_r(&now, &timeinfo);
  Serial.print("Current time: ");
  Serial.print(asctime(&timeinfo));

  //Make HTTPS POST request to send notification
  if (WiFi.status() == WL_CONNECTED) {
    // Create a JSON object with notification details
    // Check the API parameters: https://pushover.net/api
    StaticJsonDocument<170> notification;

    notification["token"] = apiToken;

    notification["user"] = userToken;

	  notification["title"] = "Thanh Phúc";

    notification["message"] = "Đã phát hiện tấn công hủy xác thực";
	
	  // notification["device"] = "ANONYMOUS";

    // notification["url"] = "";

    // notification["url_title"] = "";

    // notification["html"] = "";

    // notification["priority"] = "";

    notification["sound"] = "detected";

    // notification["timestamp"] = "";

    // Serialize the JSON object to a string
    String jsonStringNotification;
    serializeJson(notification, jsonStringNotification);
    // Create a WiFiClientSecure object
    WiFiClientSecure client;
    // Set the certificate
    client.setTrustAnchors(&cert);
    // Create an HTTPClient object
    HTTPClient http;
    // Specify the target URL
    http.begin(client, pushoverApiEndpoint);
    // Add headers
    http.addHeader("Content-Type", "application/json");
    // Send the POST request with the JSON data
    int httpResponseCode = http.POST(jsonStringNotification);
    // Check the response
    if (httpResponseCode > 0) {
      Serial.printf("HTTP response code: %d\n", httpResponseCode);
      String response = http.getString();
      Serial.println("Response:");
      Serial.println(response);
    } else {
      Serial.printf("HTTP response code: %d\n", httpResponseCode);
    }
    // Close the connection
    http.end();
  }
}


void connected() {
  Serial.begin(115200);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");
  // Set time via NTP, as required for x.509 validation
  configTime(3 * 3600, 0, "pool.ntp.org", "time.nist.gov");
  Serial.print("Waiting for NTP time sync: ");
  time_t now = time(nullptr);
  while (now < 8 * 3600 * 2) {
    delay(100);
    Serial.print(".");
    now = time(nullptr);
  }
  Serial.println("");
  struct tm timeinfo;
  gmtime_r(&now, &timeinfo);
  Serial.print("Current time: ");
  Serial.print(asctime(&timeinfo));

  //Make HTTPS POST request to send notification
  if (WiFi.status() == WL_CONNECTED) {
    // Create a JSON object with notification details
    // Check the API parameters: https://pushover.net/api
    StaticJsonDocument<170> notification;

    notification["token"] = apiToken;

    notification["user"] = userToken;

    notification["message"] = "Hệ thống phát hiện tấn công đã sẵn sàng";

    notification["title"] = "Thanh Phúc";

    // notification["url"] = "";

    // notification["url_title"] = "";

    // notification["html"] = "";

    // notification["priority"] = "";

    notification["sound"] = "connected";

    // notification["timestamp"] = "";

    // Serialize the JSON object to a string
    String jsonStringNotification;
    serializeJson(notification, jsonStringNotification);
    // Create a WiFiClientSecure object
    WiFiClientSecure client;
    // Set the certificate
    client.setTrustAnchors(&cert);
    // Create an HTTPClient object
    HTTPClient http;
    // Specify the target URL
    http.begin(client, pushoverApiEndpoint);
    // Add headers
    http.addHeader("Content-Type", "application/json");
    // Send the POST request with the JSON data
    int httpResponseCode = http.POST(jsonStringNotification);
    // Check the response
    if (httpResponseCode > 0) {
      Serial.printf("HTTP response code: %d\n", httpResponseCode);
      String response = http.getString();
      Serial.println("Response:");
      Serial.println(response);
    } else {
      Serial.printf("HTTP response code: %d\n", httpResponseCode);
    }
    // Close the connection
    http.end();
  }
}


// ===== Sniffer function ===== //
void sniffer(uint8_t* buf, uint16_t len) {
  if (!buf || len < 28) return;  // Drop packets without MAC header
  byte pkt_type = buf[12];       // second half of frame control field
  //byte* addr_a = &buf[16]; // first MAC address
  //byte* addr_b = &buf[22]; // second MAC address
  // If captured packet is a deauthentication or dissassociaten frame
  if (pkt_type == 0xA0 || pkt_type == 0xC0) {
    ++packet_rate;
  }
}

// ===== Attack detection functions ===== //
void attack_started() {
  digitalWrite(LED, !LED_INVERT);  // turn LED on
   Serial.println("ATTACK DETECTED");
}

void attack_stopped() {
  digitalWrite(LED, LED_INVERT);  // turn LED off
  Serial.begin(115200);
  Serial.println("ATTACK STOPPED");
  delay(500);
  wifi_promiscuous_enable(false);  // Tắt sniffer để có thể connect() lại được với Wi-Fi và gửi thông báo
  connect();
  wifi_promiscuous_enable(true); // Bật lại sniffer để  tiếp tục đánh hơi
  //  Serial.println("Da bat lai che do sniffer");
  // Khi cuộc tấn công dừng lại thì mạch ESP8266 sẽ restart lại và khi đó sẽ hiển thị thông báo trên các thiết bị như android, windows,...
  // ESP.restart();
}

// ===== Setup ===== //
void setup() {
  connected();
  Serial.begin(SERIAL_BAUD);  // Start serial communication
  pinMode(LED, OUTPUT);       // Enable LED pin
  digitalWrite(LED, LED_INVERT);
  WiFi.disconnect();                    // Disconnect from any saved or active WiFi connections
  wifi_set_opmode(STATION_MODE);        // Set device to client/station mode
  wifi_set_promiscuous_rx_cb(sniffer);  // Set sniffer function
  wifi_set_channel(channels[0]);        // Set channel
  wifi_promiscuous_enable(true);        // Enable sniffer
  Serial.println("");
  Serial.println("Started \\o/");
}

// ===== Loop ===== //
void loop() {
  unsigned long current_time = millis();  // Get current time (in ms)
  // Update each second (or scan-time-per-channel * channel-range)
  if (current_time - update_time >= (sizeof(channels) * CH_TIME)) {
    update_time = current_time;  // Update time variable
    // When detected deauth packets exceed the minimum allowed number
    if (packet_rate >= PKT_RATE) {
      ++attack_counter;  // Increment attack counter
    } else {
      if (attack_counter >= PKT_TIME) attack_stopped();
      attack_counter = 0;  // Reset attack counter
    }
    // When attack exceeds minimum allowed time
    if (attack_counter == PKT_TIME) {
      attack_started();
    }
    Serial.print("Packets/s: ");
    Serial.println(packet_rate);
    packet_rate = 0;  // Reset packet rate
  }
  // Channel hopping
  if (sizeof(channels) > 1 && current_time - ch_time >= CH_TIME) {
    ch_time = current_time;  // Update time variable
    // Get next channel
    ch_index = (ch_index + 1) % (sizeof(channels) / sizeof(channels[0]));
    short ch = channels[ch_index];
    // Set channel
    //Serial.print("Set channel to ");
    //Serial.println(ch);
    wifi_set_channel(ch);
  }
}
