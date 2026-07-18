package health

import "testing"

// Trimmed real `smartctl -a` output from a SAMSUNG MZ7L3 SATA SSD (titan).
// Wearout must come from attr 177 Wear_Leveling_Count (remaining-style,
// VALUE 098 → 2% used) and temperature from attr 194's RAW_VALUE (35), not
// from the leading 0 of the hex FLAG column.
const samsungSATASmart = `=== START OF INFORMATION SECTION ===
Device Model:     SAMSUNG MZ7L3960HCJR-00A07
Serial Number:    S662NE0T408957
Rotation Rate:    Solid State Device

=== START OF READ SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

SMART Attributes Data Structure revision number: 1
Vendor Specific SMART Attributes with Thresholds:
ID# ATTRIBUTE_NAME          FLAG     VALUE WORST THRESH TYPE      UPDATED  WHEN_FAILED RAW_VALUE
  5 Reallocated_Sector_Ct   0x0033   100   100   010    Pre-fail  Always       -       0
  9 Power_On_Hours          0x0032   097   097   000    Old_age   Always       -       14393
177 Wear_Leveling_Count     0x0013   098   098   005    Pre-fail  Always       -       136
190 Airflow_Temperature_Cel 0x0032   065   054   000    Old_age   Always       -       35
194 Temperature_Celsius     0x0022   065   054   000    Old_age   Always       -       35 (Min/Max 20/46)
241 Total_LBAs_Written      0x0032   099   099   000    Old_age   Always       -       103255905297
`

const nvmeSmart = `=== START OF INFORMATION SECTION ===
Model Number:                       SAMSUNG MZ1L21T9HCLS-00A07
Serial Number:                      S666NN0X706036

=== START OF SMART DATA SECTION ===
SMART overall-health self-assessment test result: PASSED

SMART/Health Information (NVMe Log 0x02)
Critical Warning:                   0x00
Temperature:                        37 Celsius
Percentage Used:                    14%
`

func TestParseSmartInfo_SamsungSATA(t *testing.T) {
	info := parseSmartInfo("/dev/sda", []byte(samsungSATASmart))
	if info.Health != "PASS" {
		t.Fatalf("health=%q want PASS", info.Health)
	}
	if info.TempC != "35" {
		t.Fatalf("temp=%q want 35 (must read attr RAW_VALUE, not the hex FLAG)", info.TempC)
	}
	if info.WearoutPctUsed == nil {
		t.Fatalf("wearout not detected — attr 177 Wear_Leveling_Count should map to remaining-style")
	}
	if *info.WearoutPctUsed != 2 {
		t.Fatalf("wearout_pct_used=%d want 2 (100 - VALUE 098)", *info.WearoutPctUsed)
	}
	if info.WearoutSource != "ata.attr.177(wear_leveling_count).value_remaining" {
		t.Fatalf("wearout_source=%q", info.WearoutSource)
	}
	if info.Model != "SAMSUNG MZ7L3960HCJR-00A07" {
		t.Fatalf("model=%q", info.Model)
	}
	if info.Type != "SSD" {
		t.Fatalf("type=%q want SSD", info.Type)
	}
}

func TestParseSmartInfo_NVMe(t *testing.T) {
	info := parseSmartInfo("/dev/nvme0", []byte(nvmeSmart))
	if info.Health != "PASS" {
		t.Fatalf("health=%q want PASS", info.Health)
	}
	if info.TempC != "37" {
		t.Fatalf("temp=%q want 37", info.TempC)
	}
	if info.WearoutPctUsed == nil || *info.WearoutPctUsed != 14 {
		t.Fatalf("wearout=%v want 14 (nvme percentage used)", info.WearoutPctUsed)
	}
	if info.WearoutSource != "nvme.percentage_used" {
		t.Fatalf("wearout_source=%q", info.WearoutSource)
	}
	if info.Type != "NVMe" {
		t.Fatalf("type=%q want NVMe", info.Type)
	}
}
