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

// CVE ve Standart Kod Format Kontrolu
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

	deviceModel := readInput("Cihaz/Robot Modeli (Orn: Robot-Kaynak-Hucresi-X1): ")
	manufacturer := readInput("Uretici Firma (Orn: TechCorp): ")
	firmwareCode := readInput("Yazilim Surumu (Orn: v1.0.0): ")
	safetySLSLimit := "SLS_MAX_SPEED_250_MM_S" // Onayli Emniyet Hiz Siniri

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

	fmt.Println("\nGecerli Formatlar: 'CVE-YYYY-XXXX' veya Standart Kod (Orn: SAFETY_SLS_TAMPERING)")
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
	fmt.Println("\n--- [4] 2027 MAKINE EMNIYETI: SLS HIZ MANIPULASYON TESTI ---")
	certID := readInput("Test Edilecek Robot Sertifika No: ")

	cert, exists := WorldState[certID]
	if !exists {
		fmt.Println("[HATA] Sertifika bulunamadi.")
		return
	}

	fmt.Println("Senaryo: Hacker Safety PLC'ye sizip SLS hiz limitini degistirmeye calisiyor.")
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

func listAllCertsCLI() {
	fmt.Println("\n--- [5] BLOKZINCIR DEFTERI (WORLD STATE) ---")
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
		fmt.Println("4. Robot SLS Emniyet Kalkani Testi (2027)")
		fmt.Println("5. Tum Blokzincir Defterini Listele")
		fmt.Println("6. Cikis")
		fmt.Println("------------------------------------------")

		choice := readInput("Seciminiz (1-6): ")

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
			listAllCertsCLI()
		case "6":
			fmt.Println("Sistemden cikiliyor...")
			return
		default:
			fmt.Println("[HATA] Gecersiz secim (1-6).")
		}
	}
}
