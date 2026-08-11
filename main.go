package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

type Certificate struct {
	CertID       string   `json:"certId"`
	DeviceModel  string   `json:"deviceModel"`
	Manufacturer string   `json:"manufacturer"`
	FirmwareHash string   `json:"firmwareHash"`
	Status       string   `json:"status"`
	Standards    []string `json:"standards"`
	IssueDate    string   `json:"issueDate"`
	RevokeReason string   `json:"revokeReason,omitempty"`
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

func issueCertCLI() {
	fmt.Println("\n--- [1] YENI CE SERTIFIKASI BASMA ---")
	certID := readInput("Sertifika Numarasi (Orn: CE-2026-001): ")
	if certID == "" {
		fmt.Println("[HATA] Sertifika numarasi bos birakilamaz.")
		return
	}

	if _, exists := WorldState[certID]; exists {
		fmt.Println("[HATA] Bu numarada bir sertifika zaten blokzincirde kayitli!")
		return
	}

	deviceModel := readInput("Cihaz Modeli (Orn: Akilli-Kamera-X1): ")
	manufacturer := readInput("Uretici Firma (Orn: TechCorp): ")
	firmwareCode := readInput("Yazilim Surumu/Kodu (Orn: v1.0.0): ")

	firmwareHash := hashData(firmwareCode)

	cert := Certificate{
		CertID:       certID,
		DeviceModel:  deviceModel,
		Manufacturer: manufacturer,
		FirmwareHash: firmwareHash,
		Status:       "VALID",
		Standards:    []string{"EU-CRA-2024", "ETSI-EN-303-645"},
		IssueDate:    time.Now().Format("2006-01-02 15:04:05"),
	}

	WorldState[certID] = cert
	fmt.Printf("\n[BASARILI] %s nolu sertifika basildi ve blokzincire kaydedildi!\n", certID)
	fmt.Printf("Hesaplanan SHA-256 Hash: %s\n", firmwareHash)
}

func queryCertCLI() {
	fmt.Println("\n--- [2] SERTIFIKA DOGRULAMA / SORGULAMA ---")
	certID := readInput("Sorgulanacak Sertifika No: ")

	cert, exists := WorldState[certID]
	if !exists {
		fmt.Println("\n[HATA] Sertifika bulunamadi! (Sahte veya kayitsiz belge)")
		return
	}

	currentFirmware := readInput("Cihazdaki Mevcut Yazilim Surumu/Kodu: ")
	currentHash := hashData(currentFirmware)

	fmt.Println("\n================ SONUC ================")
	if cert.Status == "REVOKED" {
		fmt.Println("[DURUM] REDDEDILDI: Bu sertifika IPTAL EDILMISTIR!")
		fmt.Printf("Iptal Gerekcesi : %s\n", cert.RevokeReason)
		return
	}

	if cert.FirmwareHash != currentHash {
		fmt.Println("[DURUM] GUVENLIK UYARISI: Cihaz yazilimi sertifikadaki hash ile uyusmuyor!")
		fmt.Printf("Beklenen Hash : %s\n", cert.FirmwareHash)
		fmt.Printf("Mevcut Hash   : %s\n", currentHash)
		return
	}

	fmt.Println("[DURUM] GECERLI: Cihaz CE siber guvenlik standartlarina uygundur.")
	fmt.Printf("Uretici     : %s\n", cert.Manufacturer)
	fmt.Printf("Model       : %s\n", cert.DeviceModel)
	fmt.Printf("Standartlar : %v\n", cert.Standards)
	fmt.Printf("Duzenleme   : %s\n", cert.IssueDate)
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

	reason := readInput("Iptal / Zafiyet Nedeni (Orn: CVE-2026-9999): ")
	cert.Status = "REVOKED"
	cert.RevokeReason = reason
	WorldState[certID] = cert

	fmt.Printf("\n[ISLEM TAMAM] %s nolu sertifika IPTAL EDILDI (Status: REVOKED)\n", certID)
}

func listAllCertsCLI() {
	fmt.Println("\n--- [4] BLOKZINCIR DEFTERI (WORLD STATE) ---")
	if len(WorldState) == 0 {
		fmt.Println("Defterde kayitli sertifika bulunmamaktadir.")
		return
	}

	for id, cert := range WorldState {
		fmt.Printf("[%s] %s (%s) - Durum: %s | Hash: %.10s...\n",
			id, cert.DeviceModel, cert.Manufacturer, cert.Status, cert.FirmwareHash)
	}
}

func main() {
	for {
		fmt.Println("\n==========================================")
		fmt.Println("  HYPERLEDGER CE SIBER GUVENLIK SISTEMI   ")
		fmt.Println("==========================================")
		fmt.Println("1. Yeni CE Sertifikasi Bas (Issue)")
		fmt.Println("2. Sertifika Dogrula / Sorgula (Verify)")
		fmt.Println("3. Sertifikayi Iptal Et (Revoke)")
		fmt.Println("4. Tum Blokzincir Defterini Listele")
		fmt.Println("5. Cikis")
		fmt.Println("------------------------------------------")

		choice := readInput("Seciminiz (1-5): ")

		switch choice {
		case "1":
			issueCertCLI()
		case "2":
			queryCertCLI()
		case "3":
			revokeCertCLI()
		case "4":
			listAllCertsCLI()
		case "5":
			fmt.Println("Sistemden cikiliyor...")
			return
		default:
			fmt.Println("[HATA] Gecersiz secim, lutfen 1-5 arasi bir sayi girin.")
		}
	}
}
