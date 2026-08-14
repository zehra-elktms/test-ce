package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Certificate struct {
	CertID           string   `json:"certId"`
	DeviceModel      string   `json:"deviceModel"`
	Manufacturer     string   `json:"manufacturer"`
	FirmwareHash     string   `json:"firmwareHash"`
	GoldenSafetyHash string   `json:"goldenSafetyHash"` // SLS Emniyet Parametresi Muhru
	Status           string   `json:"status"`           // VALID, REVOKED, SAFE_STATE
	Standards        []string `json:"standards"`
	IssueDate        string   `json:"issueDate"`
	RevokeReason     string   `json:"revokeReason,omitempty"`
}

var WorldState = make(map[string]Certificate)
var scanner = bufio.NewScanner(os.Stdin)

func hashData(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func readInput(prompt string) string {
	fmt.Print(prompt)
	scanner.Scan()
	return strings.TrimSpace(scanner.Text())
}

func isValidRevokeReason(reason string) bool {
	cveRegex := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	if cveRegex.MatchString(reason) {
		return true
	}
	standardCodes := []string{
		"CRA_UNPATCHED_VULNERABILITY",
		"SAFETY_SLS_TAMPERING",
		"UNAUTHORIZED_OVERRIDE",
		"FALSE_DECLARATION",
		"SENSOR_SPOOFING_DETECTED",
	}
	for _, code := range standardCodes {
		if strings.EqualFold(reason, code) {
			return true
		}
	}
	return false
}

func issueCertCLI() {
	fmt.Println("\n--- [1] YENI CE SERTIFIKASI BASMA ---")
	certID := readInput("Sertifika Numarasi (Orn: CE-2026-001): ")
	if certID == "" {
		fmt.Println("[HATA] Sertifika numarasi bos birakilamaz.")
		return
	}

	if _, exists := WorldState[certID]; exists {
		fmt.Println("[HATA] Bu sertifika zaten kayitli!")
		return
	}

	deviceModel := readInput("Cihaz/Robot Modeli (Orn: Kimyasal-Kazan-Sistemi-K1): ")
	manufacturer := readInput("Uretici Firma (Orn: TechCorp): ")
	firmwareCode := readInput("Yazilim Surumu (Orn: v1.0.0): ")
	safetySLSLimit := "SLS_MAX_SPEED_250_MM_S"

	firmwareHash := hashData(firmwareCode)
	goldenSafetyHash := hashData(safetySLSLimit)

	cert := Certificate{
		CertID:           certID,
		DeviceModel:      deviceModel,
		Manufacturer:     manufacturer,
		FirmwareHash:     firmwareHash,
		GoldenSafetyHash: goldenSafetyHash,
		Status:           "VALID",
		Standards:        []string{"EU-Machinery-2023/1230", "EU-CRA-2024", "EN-303-645"},
		IssueDate:        time.Now().Format("2006-01-02 15:04:05"),
	}

	WorldState[certID] = cert
	fmt.Printf("\n[BASARILI] %s nolu CE sertifikasi basilmistir.\n", certID)
	fmt.Printf("Altin Emniyet Muhru (SLS Hash): %s\n", goldenSafetyHash)
}

func queryCertCLI() {
	fmt.Println("\n--- [2] SERTIFIKA DOGRULAMA / SORGULAMA ---")
	certID := readInput("Sorgulanacak Sertifika No: ")

	cert, exists := WorldState[certID]
	if !exists {
		fmt.Println("[HATA] Sertifika bulunamadi! Sahte veya kayitsiz belge.")
		return
	}

	currentFirmware := readInput("Cihazdaki Mevcut Yazilim Surumu: ")
	currentHash := hashData(currentFirmware)

	fmt.Println("\n================ SONUC ================")
	if cert.Status == "REVOKED" {
		fmt.Println("[DURUM] REDDEDILDI: Bu sertifika IPTAL EDILMISTIR!")
		fmt.Printf("Iptal Gerekcesi : %s\n", cert.RevokeReason)
		return
	}

	if cert.FirmwareHash != currentHash {
		fmt.Println("[DURUM] GUVENLIK UYARISI: Yazilim hash uyusmazligi tespit edildi!")
		return
	}

	fmt.Println("[DURUM] GECERLI: Cihaz CE siber guvenlik standartlarina uygundur.")
	fmt.Printf("Uretici     : %s\n", cert.Manufacturer)
	fmt.Printf("Model       : %s\n", cert.DeviceModel)
	fmt.Printf("Standartlar : %v\n", cert.Standards)
	fmt.Println("========================================")
}

func revokeCertCLI() {
	fmt.Println("\n--- [3] SERTIFIKA IPTAL ET (REVOCATION) ---")
	certID := readInput("Iptal Edilecek Sertifika No: ")

	cert, exists := WorldState[certID]
	if !exists {
		fmt.Println("[HATA] Sertifika bulunamadi.")
		return
	}

	if cert.Status == "REVOKED" {
		fmt.Println("[UYARI] Bu sertifika zaten onceden iptal edilmistir!")
		return
	}

	fmt.Println("\nGecerli Formatlar: 'CVE-YYYY-XXXX' veya Standart Kod (Orn: SENSOR_SPOOFING_DETECTED)")
	reason := readInput("Iptal / Zafiyet Gerekcesi: ")

	if !isValidRevokeReason(reason) {
		fmt.Println("\n[HATA] DOGRULAMA BASARISIZ: Iptal gerekcesi standart regulasyon formatina uygun degildir.")
		fmt.Println("[REDDEDILDI] Gerekce uluslararasi 'CVE-YYYY-XXXX' formatinda veya tanimli Guvenlik Kodu olmalidir.")
		return
	}

	cert.Status = "REVOKED"
	cert.RevokeReason = reason
	WorldState[certID] = cert

	fmt.Printf("\n[ISLEM TAMAM] %s nolu sertifika basariyla IPTAL EDILDI.\n", certID)
}

func testSafetySLSCLI() {
	fmt.Println("\n--- [4] RISK 2: ROBOT SLS HIZ MANIPULASYON TESTI ---")
	certID := readInput("Test Edilecek Robot Sertifika No: ")

	cert, exists := WorldState[certID]
	if !exists {
		fmt.Println("[HATA] Sertifika bulunamadi.")
		return
	}

	fmt.Println("Senaryo: Saldirgan Safety PLC'ye sizip SLS hiz limitini yukseltmeye calisiyor.")
	speedInput := readInput("PLC'ye Enjekte Edilmeye Calisilan Hiz (mm/s) [Orn: 250 veya 2500]: ")
	speed, err := strconv.Atoi(speedInput)
	if err != nil {
		fmt.Println("[HATA] Gecerli bir sayi giriniz.")
		return
	}

	currentParam := fmt.Sprintf("SLS_MAX_SPEED_%d_MM_S", speed)
	currentHash := hashData(currentParam)

	if currentHash != cert.GoldenSafetyHash || speed > 250 {
		fmt.Println("\n[ALARM] 5 HALKALI ETKI ZINCIRI YAKALANDI!")
		fmt.Println(" - 1. Saldiri: Hiz Parametresi Manipulasyonu")
		fmt.Println(" - 2. Hedef  : Safety PLC / Servo Surucu")
		fmt.Println(" - 3. Degisim: Hiz Limiti 250 mm/s yerine " + speedInput + " mm/s yapilmak istendi")
		fmt.Println(" - 4. Emniyet: SLS (Guvenli Hiz) Devre Disi Kalma Riski")
		fmt.Println(" - 5. Sonuc  : KAZA ONLENDI! Altin Hash Uyusmadi -> Robot SAFE-STATE (Acil Fren) Moduna Gecti!")
	} else {
		fmt.Println("\n[ONAYLANDI] Emniyet parametresi Altin Muhur ile uyusuyor. SLS Guvenli (250 mm/s).")
	}
}

func testMultiSigFirmwareCLI() {
	fmt.Println("\n--- [5] RISK 1: E-STOP KORUMASI VE COKLU IMZALI FIRMWARE YUKLEME ---")
	certID := readInput("Guncellenecek Cihaz Sertifika No: ")

	cert, exists := WorldState[certID]
	if !exists {
		fmt.Println("[HATA] Sertifika bulunamadi.")
		return
	}

	fmt.Println("Senaryo: Yeni bir yazilim yuklenerek E-Stop iptal edilmeye calisiliyor.")
	newFirmware := readInput("Yuklenmek Istenen Yeni Firmware Surumu (Orn: v2.0.0): ")
	mfgSignature := readInput("Uretici Dijital Imzasi (Orn: SIG_TECHCORP_OK veya GECERSIZ): ")
	notifiedBodySignature := readInput("Onaylanmis Kurulus (TUV) Dijital Imzasi (Orn: SIG_TUV_AUDIT_OK veya GECERSIZ): ")

	if mfgSignature != "SIG_TECHCORP_OK" || notifiedBodySignature != "SIG_TUV_AUDIT_OK" {
		fmt.Println("\n[ALARM] TEHLIKELI YAZILIM YUKLEME GIRISIMI ENGELLENDI!")
		fmt.Println(" - Tespit  : Cift tarafli resmi denetim imzasi bulunamadi (Multi-Sig Eksik).")
		fmt.Println(" - Emniyet : E-Stop (Acil Durdurma) fonksiyonunun bozulma riski onlendi.")
		fmt.Println(" - Sonuc   : Blokzincir konsensusu firmware yuklemesini REDDETTI!")
		return
	}

	cert.FirmwareHash = hashData(newFirmware)
	WorldState[certID] = cert
	fmt.Println("\n[BASARILI] Cift tarafli denetim onaylandi. Guvenli Firmware blokzincire islendi.")
}

func testSensorSpoofingCLI() {
	fmt.Println("\n--- [6] RISK 3: SENSOR YANILTMA VE KAZAN PATLAMA KALKANI (DID) ---")
	fmt.Println("Senaryo: Kimyasal kazan gercekte 850 C iken saldirgan sensor hattina sahte '120 C' sinyali enjekte ediyor.")

	sensorDID := readInput("Sensor Kriptografik Kimligi / DID (Orn: DID_TEMP_SENSOR_01 veya SAHTE_DID): ")
	sensorSignature := readInput("Sensor Kriptografik Imzasi (Orn: SIG_KEY_SENSOR_VALID veya GECERSIZ): ")
	reportedTempInput := readInput("Sensorun Bildirdigi Sicaklik Degeri (C): ")

	temp, err := strconv.Atoi(reportedTempInput)
	if err != nil {
		fmt.Println("[HATA] Gecerli bir sicaklik degeri giriniz.")
		return
	}

	if sensorDID != "DID_TEMP_SENSOR_01" || sensorSignature != "SIG_KEY_SENSOR_VALID" {
		fmt.Println("\n[ALARM] SENSOR VERI ENJEKSIYONU (SPOOFING) TESPIT EDILDI!")
		fmt.Println(" - 1. Saldiri: Sensor Haberlesme Hattina Sahte Veri Enjeksiyonu")
		fmt.Println(" - 2. Hedef  : Termal/Basinc Emniyet Sensoru")
		fmt.Println(" - 3. Degisim: Kriptografik kimlik (DID) ve imza dogrulanamadi")
		fmt.Println(" - 4. Emniyet: Safe Thermal Cut-off (Guvenli Termal Kapatma) Baypas Riski")
		fmt.Println(" - 5. Sonuc  : KAZA ONLENDI! ACIL TERMAL KAPATMA DEVREYE GIRDI -> Kazan Patlamasi Engellendi!")
		return
	}

	if temp > 300 {
		fmt.Printf("\n[ALARM] ASIRI SICAKLIK TESPITI (%d C)! Otomatik sogutma valfleri acildi.\n", temp)
	} else {
		fmt.Printf("\n[ONAYLANDI] Sensor kimligi dogrulandi. Sicaklik (%d C) guvenli aralikta.\n", temp)
	}
}

func listAllCertsCLI() {
	fmt.Println("\n--- [7] BLOKZINCIR DEFTERI (WORLD STATE) ---")
	if len(WorldState) == 0 {
		fmt.Println("Defterde kayitli sertifika yok.")
		return
	}
	for id, cert := range WorldState {
		fmt.Printf("[%s] %s (%s) - Durum: %s\n", id, cert.DeviceModel, cert.Manufacturer, cert.Status)
	}
}

func main() {
	for {
		fmt.Println("\n==========================================")
		fmt.Println("  HYPERLEDGER CE SIBER-EMNIYET SISTEMI    ")
		fmt.Println("==========================================")
		fmt.Println("1. Yeni CE Sertifikasi Bas (Issue)")
		fmt.Println("2. Sertifika Dogrula / Sorgula (Verify)")
		fmt.Println("3. Sertifikayi Iptal Et (CVE Format Kontrollu)")
		fmt.Println("4. Risk 2: Robot SLS Emniyet Kalkani Testi")
		fmt.Println("5. Risk 1: Coklu Imzali Firmware (E-Stop Koruma)")
		fmt.Println("6. Risk 3: Sensor Yaniltma ve Patlama Kalkani")
		fmt.Println("7. Tum Blokzincir Defterini Listele")
		fmt.Println("8. Cikis")
		fmt.Println("------------------------------------------")

		choice := readInput("Seciminiz (1-8): ")

		switch choice {
		case "1":
			issueCertCLI()
		case "2":
			queryCertCLI()
		case "3":
			revokeCertCLI()
		case "4":
			testSafetySLSCLI()
		case "5":
			testMultiSigFirmwareCLI()
		case "6":
			testSensorSpoofingCLI()
		case "7":
			listAllCertsCLI()
		case "8":
			fmt.Println("Sistemden cikiliyor...")
			return
		default:
			fmt.Println("[HATA] Gecersiz secim (1-8).")
		}
	}
}
