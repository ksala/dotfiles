// Most configurations copy/pasted from https://github.com/pyllyukko/user.js

// PREF: Disable Service Workers
// https://developer.mozilla.org/en-US/docs/Web/API/Worker
// https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorker_API
// https://wiki.mozilla.org/Firefox/Push_Notifications#Service_Workers
// NOTICE: Disabling ServiceWorkers breaks functionality on some sites (Google Street View...)
// Unknown security implications
// CVE-2016-5259, CVE-2016-2812, CVE-2016-1949, CVE-2016-5287 (fixed)
user_pref("dom.serviceWorkers.enabled", false);

// PREF: Disable Web Workers
// https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers
// https://www.w3schools.com/html/html5_webworkers.asp
// NOTICE: Disabling Web Workers breaks "Download as ZIP" functionality on https://mega.nz/, WhatsApp Web and probably others
user_pref("dom.workers.enabled",					false);

// PREF: Disable web notifications
// https://support.mozilla.org/t5/Firefox/I-can-t-find-Firefox-menu-I-m-trying-to-opt-out-of-Web-Push-and/m-p/1317495#M1006501
user_pref("dom.webnotifications.enabled",			false);

// PREF: Disable DOM timing API
// https://wiki.mozilla.org/Security/Reviews/Firefox/NavigationTimingAPI
// https://www.w3.org/TR/navigation-timing/#privacy
user_pref("dom.enable_performance",				false);

// PREF: Make sure the User Timing API does not provide a new high resolution timestamp
// https://trac.torproject.org/projects/tor/ticket/16336
// https://www.w3.org/TR/2013/REC-user-timing-20131212/#privacy-security
user_pref("dom.enable_user_timing",				false);

// PREF: Disable Web Audio API
// https://bugzilla.mozilla.org/show_bug.cgi?id=1288359
user_pref("dom.webaudio.enabled",				false);

// PREF: Disable Location-Aware Browsing (geolocation)
// https://www.mozilla.org/en-US/firefox/geolocation/
user_pref("geo.enabled",					false);

// PREF: Disable raw TCP socket support (mozTCPSocket)
// https://trac.torproject.org/projects/tor/ticket/18863
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-97/
// https://developer.mozilla.org/docs/Mozilla/B2G_OS/API/TCPSocket
user_pref("dom.mozTCPSocket.enabled", false);

// PREF: Disable leaking network/browser connection information via Javascript
// Network Information API provides general information about the system's connection type (WiFi, cellular, etc.)
// https://developer.mozilla.org/en-US/docs/Web/API/Network_Information_API
// https://wicg.github.io/netinfo/#privacy-considerations
// https://bugzilla.mozilla.org/show_bug.cgi?id=960426
user_pref("dom.netinfo.enabled", false);

// PREF: Don't reveal your internal IP when WebRTC is enabled (Firefox >= 42)
// https://wiki.mozilla.org/Media/WebRTC/Privacy
// https://github.com/beefproject/beef/wiki/Module%3A-Get-Internal-IP-WebRTC
user_pref("media.peerconnection.ice.no_host", true); // Firefox >= 52

// PREF: Disable telephony API
// https://wiki.mozilla.org/WebAPI/Security/WebTelephony
user_pref("dom.telephony.enabled",				false);

// PREF: Disable "beacon" asynchronous HTTP transfers (used for analytics)
// https://developer.mozilla.org/en-US/docs/Web/API/navigator.sendBeacon
user_pref("beacon.enabled", false);

// PREF: Disable speech recognition
// https://dvcs.w3.org/hg/speech-api/raw-file/tip/speechapi.html
// https://developer.mozilla.org/en-US/docs/Web/API/SpeechRecognition
// https://wiki.mozilla.org/HTML5_Speech_API
user_pref("media.webspeech.recognition.enable",			false);

// PREF: Disable speech synthesis
// https://developer.mozilla.org/en-US/docs/Web/API/SpeechSynthesis
user_pref("media.webspeech.synth.enabled",			false);

// PREF: Disable sensor API
// https://wiki.mozilla.org/Sensor_API
user_pref("device.sensors.enabled",				false);

// PREF: Disable pinging URIs specified in HTML <a> ping= attributes
// http://kb.mozillazine.org/Browser.send_pings
user_pref("browser.send_pings",					false);

// PREF: Disable gamepad API to prevent USB device enumeration
// https://www.w3.org/TR/gamepad/
// https://trac.torproject.org/projects/tor/ticket/13023
user_pref("dom.gamepad.enabled",				false);

// PREF: Disable virtual reality devices APIs
// https://developer.mozilla.org/en-US/Firefox/Releases/36#Interfaces.2FAPIs.2FDOM
// https://developer.mozilla.org/en-US/docs/Web/API/WebVR_API
user_pref("dom.vr.enabled",					false);

// PREF: Disable vibrator API
user_pref("dom.vibrator.enabled",           false);

// PREF: Disable resource timing API
// https://www.w3.org/TR/resource-timing/#privacy-security
user_pref("dom.enable_resource_timing",				false);

// PREF: Disable webGL
// https://en.wikipedia.org/wiki/WebGL
// https://www.contextis.com/resources/blog/webgl-new-dimension-browser-exploitation/
user_pref("webgl.disabled",					true);
// PREF: When webGL is enabled, use the minimum capability mode
user_pref("webgl.min_capability_mode",				true);
// PREF: When webGL is enabled, disable webGL extensions
// https://developer.mozilla.org/en-US/docs/Web/API/WebGL_API#WebGL_debugging_and_testing
user_pref("webgl.disable-extensions",				true);
// PREF: When webGL is enabled, force enabling it even when layer acceleration is not supported
// https://trac.torproject.org/projects/tor/ticket/18603
user_pref("webgl.disable-fail-if-major-performance-caveat",	true);
// PREF: When webGL is enabled, do not expose information about the graphics driver
// https://bugzilla.mozilla.org/show_bug.cgi?id=1171228
// https://developer.mozilla.org/en-US/docs/Web/API/WEBGL_debug_renderer_info
user_pref("webgl.enable-debug-renderer-info",			false);
// Disable WebGl 2
user_pref("webgl.enable-webgl2",    false);
// somewhat related...
user_pref("pdfjs.enableWebGL",					false);

// PREF: Disable face detection
user_pref("camera.control.face_detection.enabled",		false);

// PREF: Set the default search engine to DuckDuckGo
// https://support.mozilla.org/en-US/questions/948134
user_pref("browser.search.defaultenginename",		"DuckDuckGo");
user_pref("browser.search.order.1",				"DuckDuckGo");
user_pref("keyword.URL", 							"https://duckduckgo.com/?q=!+");  

// PREF: Disable GeoIP lookup on your address to set default search engine region
// https://trac.torproject.org/projects/tor/ticket/16254
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_geolocation-for-default-search-engine
user_pref("browser.search.countryCode",				"US");
user_pref("browser.search.region",				"US");
user_pref("browser.search.geoip.url",				"");

// PREF: Set Accept-Language HTTP header to en-US regardless of Firefox localization
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Language
user_pref("intl.accept_languages",				"en-us, en");

// PREF: Don't use OS values to determine locale, force using Firefox locale setting
// http://kb.mozillazine.org/Intl.locale.matchOS
user_pref("intl.locale.matchOS",				false);

// PREF: Don't use Mozilla-provided location-specific search engines
user_pref("browser.search.geoSpecificDefaults",			false);

// PREF: Do not automatically send selection to clipboard on some Linux platforms
// http://kb.mozillazine.org/Clipboard.autocopy
user_pref("clipboard.autocopy",					false);

// PREF: Prevent leaking application locale/date format using JavaScript
// https://bugzilla.mozilla.org/show_bug.cgi?id=867501
// https://hg.mozilla.org/mozilla-central/rev/52d635f2b33d
user_pref("javascript.use_us_english_locale", true);

// PREF: Disable asm.js
// http://asmjs.org/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-29/
// https://www.mozilla.org/en-US/security/advisories/mfsa2015-50/
// https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-2712
user_pref("javascript.options.asmjs", false);

// Disable WebAssembly
// https://github.com/stevespringett/disable-webassembly
user_pref("javascript.options.wasm", false);

// PREF: Disable video stats to reduce fingerprinting threat
// https://bugzilla.mozilla.org/show_bug.cgi?id=654550
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-100468785
// https://github.com/pyllyukko/user.js/issues/9#issuecomment-148922065
user_pref("media.video_stats.enabled", false);

// PREF: Don't reveal build ID
// Value taken from Tor Browser
// https://bugzilla.mozilla.org/show_bug.cgi?id=583181
user_pref("general.buildID.override",				"20100101");
user_pref("browser.startup.homepage_override.buildID", "20100101");

// PREF: Opt-out of add-on metadata updates
// https://blog.mozilla.org/addons/how-to-opt-out-of-add-on-metadata-updates/
user_pref("extensions.getAddons.cache.enabled", false);

// PREF: Enable add-on and certificate blocklists (OneCRL) from Mozilla
// https://wiki.mozilla.org/Blocklisting
// https://blocked.cdn.mozilla.net/
// http://kb.mozillazine.org/Extensions.blocklist.enabled
// http://kb.mozillazine.org/Extensions.blocklist.url
// https://blog.mozilla.org/security/2015/03/03/revoking-intermediate-certificates-introducing-onecrl/
// Updated at interval defined in extensions.blocklist.interval (default: 86400)
user_pref("extensions.blocklist.enabled",			true);
user_pref("services.blocklist.update_enabled", true);

// PREF: Decrease system information leakage to Mozilla blocklist update servers
// https://trac.torproject.org/projects/tor/ticket/16931
user_pref("extensions.blocklist.url", "https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/");

// PREF: Disallow Necko to do A/B testing
// https://trac.torproject.org/projects/tor/ticket/13170
user_pref("network.allow-experiments", false);

// PREF: Disable FlyWeb (discovery of LAN/proximity IoT devices that expose a Web interface)
// https://wiki.mozilla.org/FlyWeb
// https://wiki.mozilla.org/FlyWeb/Security_scenarios
// https://docs.google.com/document/d/1eqLb6cGjDL9XooSYEEo7mE-zKQ-o-AuDTcEyNhfBMBM/edit
// http://www.ghacks.net/2016/07/26/firefox-flyweb
user_pref("dom.flyweb.enabled", false);

// PREF: Disable the UITour backend
// https://trac.torproject.org/projects/tor/ticket/19047#comment:3
user_pref("browser.uitour.enabled", false);

// PREF: Enable Firefox Tracking Protection
// https://wiki.mozilla.org/Security/Tracking_protection
// https://support.mozilla.org/en-US/kb/tracking-protection-firefox
// https://support.mozilla.org/en-US/kb/tracking-protection-pbm
// https://kontaxis.github.io/trackingprotectionfirefox/
// https://feeding.cloud.geek.nz/posts/how-tracking-protection-works-in-firefox/
user_pref("privacy.trackingprotection.enabled",			true);
user_pref("privacy.trackingprotection.pbmode.enabled", true);

// PREF: Enable contextual identity Containers feature (Firefox >= 52)
// NOTICE: Containers are not available in Private Browsing mode
// https://wiki.mozilla.org/Security/Contextual_Identity_Project/Containers
user_pref("privacy.userContext.enabled", true);

// PREF: Disable Heartbeat  (Mozilla user rating telemetry)
// https://wiki.mozilla.org/Advocacy/heartbeat
// https://trac.torproject.org/projects/tor/ticket/19047
user_pref("browser.selfsupport.url", "");

// PREF: Disable querying Google Application Reputation database for downloaded binary files
// https://www.mozilla.org/en-US/firefox/39.0/releasenotes/
// https://wiki.mozilla.org/Security/Application_Reputation
user_pref("browser.safebrowsing.downloads.remote.enabled",	false);

// PREF: Disable SHIELD
// https://support.mozilla.org/en-US/kb/shield
// https://bugzilla.mozilla.org/show_bug.cgi?id=1370801
user_pref("extensions.shield-recipe-client.enabled",		false);
user_pref("app.shield.optoutstudies.enabled",			false);
user_pref("extensions.shield-recipe-client.api_url",    "");
user_pref("extensions.shield-recipe-client.user_id",    "");

// PREF: Disable "Recommended by Pocket" in Firefox Quantum
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);

// PREF: Reject .onion hostnames before passing the to DNS
// https://bugzilla.mozilla.org/show_bug.cgi?id=1228457
// RFC 7686
user_pref("network.dns.blockDotOnion", true);

// PREF: Disable search suggestions in the search bar
// http://kb.mozillazine.org/Browser.search.suggest.enabled
user_pref("browser.search.suggest.enabled", false);

// PREF: Disable "Show search suggestions in location bar results"
user_pref("browser.urlbar.suggest.searches", false);

// PREF: Disable SSDP
// https://bugzilla.mozilla.org/show_bug.cgi?id=1111967
user_pref("browser.casting.enabled", false);

// PREF: Disable downloading homepage snippets/messages from Mozilla
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_mozilla-content
// https://wiki.mozilla.org/Firefox/Projects/Firefox_Start/Snippet_Service
user_pref("browser.aboutHomeSnippets.updateUrl", "");

// PREF: Never check updates for search engines
// https://support.mozilla.org/en-US/kb/how-stop-firefox-making-automatic-connections#w_auto-update-checking
user_pref("browser.search.update", false);

// PREF: Disallow NTLMv1
// https://bugzilla.mozilla.org/show_bug.cgi?id=828183
user_pref("network.negotiate-auth.allow-insecure-ntlm-v1", false);

// PREF: Enable CSP 1.1 script-nonce directive support
// https://bugzilla.mozilla.org/show_bug.cgi?id=855326
user_pref("security.csp.experimentalEnabled", true);


// PREF: DNT HTTP header (disabled)
// https://www.mozilla.org/en-US/firefox/dnt/
// https://en.wikipedia.org/wiki/Do_not_track_header
// https://dnt-dashboard.mozilla.org
// https://github.com/pyllyukko/user.js/issues/11
// NOTICE: Do No Track must be enabled manually
user_pref("privacy.donottrackheader.enabled",		true);

// PREF: Do not download URLs for the offline cache
// http://kb.mozillazine.org/Browser.cache.offline.enable
user_pref("browser.cache.offline.enable", false);

// Clear on close
user_pref("privacy.cpd.offlineApps", true);
user_pref("privacy.cpd.formdata", true);

// PREF: Disable password manager
// CIS Version 1.2.0 October 21st, 2011 2.5.2
user_pref("signon.rememberSignons", false);

// PREF: Disable form autofill, don't save information entered in web page forms and the Search Bar
user_pref("browser.formfill.enable", false);

// PREF: Require manual intervention to autofill known username/passwords sign-in forms
// http://kb.mozillazine.org/Signon.autofillForms
// https://www.torproject.org/projects/torbrowser/design/#identifier-linkability
user_pref("signon.autofillForms", false);

// PREF: Delete temporary files on exit
// https://bugzilla.mozilla.org/show_bug.cgi?id=238789
user_pref("browser.helperApps.deleteTempFileOnExit", true);

// PREF: Disable new tab tile ads & preload
// http://www.thewindowsclub.com/disable-remove-ad-tiles-from-firefox
// http://forums.mozillazine.org/viewtopic.php?p=13876331#p13876331
// https://wiki.mozilla.org/Tiles/Technical_Documentation#Ping
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-source
// https://gecko.readthedocs.org/en/latest/browser/browser/DirectoryLinksProvider.html#browser-newtabpage-directory-ping
// TODO: deprecated? not in DXR, some dead links
user_pref("browser.newtabpage.enhanced",			false);
user_pref("browser.newtab.preload",				false);
user_pref("browser.newtabpage.directory.ping",			"");
user_pref("browser.newtabpage.directory.source", "data:text/plain,{}");


// PREF: Force Punycode for Internationalized Domain Names
// http://kb.mozillazine.org/Network.IDN_show_punycode
// https://www.xudongz.com/blog/2017/idn-phishing/
// https://wiki.mozilla.org/IDN_Display_Algorithm
// https://en.wikipedia.org/wiki/IDN_homograph_attack
// https://www.mozilla.org/en-US/security/advisories/mfsa2017-02/
// CIS Mozilla Firefox 24 ESR v1.0.0 - 3.6
user_pref("network.IDN_show_punycode", true);

// PREF: Disable CSS :visited selectors
// https://blog.mozilla.org/security/2010/03/31/plugging-the-css-history-leak/
// https://dbaron.org/mozilla/visited-privacy
user_pref("layout.css.visited_links_enabled", false);

// PREF: Do not check if Firefox is the default browser
user_pref("browser.shell.checkDefaultBrowser", false);

// PREF: Display a notification bar when websites offer data for offline use
// http://kb.mozillazine.org/Browser.offline-apps.notify
user_pref("browser.offline-apps.notify", true);

// PREF: Enable HSTS preload list (pre-set HSTS sites list provided by Mozilla)
// https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
// https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List
// https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security
user_pref("network.stricttransportsecurity.preloadlist",	true);

// Accept third-party cookies from visited sites
user_pref("network.cookie.cookieBehavior", 3);
// Throw away third-party cookies when restarting the browser
// https://feeding.cloud.geek.nz/posts/tweaking-cookies-for-privacy-in-firefox/
user_pref("network.cookie.thirdparty.sessionOnly", true);

// For whatever reason OpenGL Off-Main-Thread Compositing remove tearing in fullscreen videos 
// Youtube and Netflix for example
// So force enable it
// https://wiki.archlinux.org/index.php/Firefox#Tearing_video_in_fullscreen_mode
// https://wiki.archlinux.org/index.php/Firefox/Tweaks#Enable_OpenGL_Off-Main-Thread_Compositing_.28OMTC.29
// https://wiki.mozilla.org/Platform/GFX/OffMainThreadCompositing
user_pref("layers.acceleration.force-enabled", true);

// Disable safe-browsing
// I know that it doesn't leak URLs to google
// But it still leaks my IP from time to time
// And I'm sure uBlock Origin and Common Sense 2018 has me covered already regarding malware
// Also I don't think I've had any warnings in the last year or so
user_pref("browser.safebrowsing.enabled",			false); // Firefox < 50
user_pref("browser.safebrowsing.phishing.enabled",		false); // firefox >= 50
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("safebrowsing.downloads.enabled", false);

// Disable JavaScript Shared Memory / sharedBufferArray
user_pref("javascript.options.shared_memory", false);

// Trim cross-origin referrers
// https://feeding.cloud.geek.nz/posts/tweaking-referrer-for-privacy-in-firefox/
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);
