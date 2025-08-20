package cmd

import (
	"io"
	"os"
	"fmt"
	"time"
	"strconv"
	"strings"
	"path"
	"net/http"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"

	"github.com/spf13/cobra"
)

var firewall bool
var typeCsv bool
var fileName string
var name string

var globalData GlobalApiReponse
var switchManagerData SwitchManagerApiReponse

type GlobalApiReponse struct {
	HTTPMethod	string `json:"http_method"`
	Results		GlobalApiResponseResults `json:"results"`
	Vdom		string `json:"vdom"`
	Status		string `json:"status"`
	HTTPStatus	int		`json:"http_status"`
	Serial		string `json:"serial"`
	Version		string `json:"version"`
	Build		int		`json:"build"`
}

type GlobalApiResponseResults struct {
	Hostname	string	`json:"hostname"`
	Timezone	string	`json:"timezone"`
}

type SwitchManagerApiReponse struct {
	HTTPMethod	string `json:"http_method"`
	MatchedCount	int `json:"matched_count"`
	Results		[]Switch `json:"results"`
	Vdom		string `json:"root"`
	Status		string `json:"status"`
	HTTPStatus	int `json:"http_status"`
	Serial		string `json:"serial"`
	Version		string `json:"version"`
	Build		int `json:"build"`
}

type Switch struct {
	SwitchId	string	`json:"switch-id"`
	Serial		string	`json:"sn"`
	Type		string	`json:"type"`
	Ports		[]SwitchPort `json:"ports"`
}

type SwitchPort struct {
	PortName	string `json:"port-name"`
	SwitchId  string `json:"switch-id"`
	Speed	string	`json:"speed"`
	Status	string	`json:"status"`
	PoeStatus string`json:"poe-status"`
	FortilinkPort int `json:"fortilink-port"`
	PoeCapable int `json:"poe-capable"`
	MclagIclPort int `json:"mclag-icl-port"`
	FiberPort int `json:"fiber-port"`
	MediaType string `json:"media-type"`
	PoeStandard string `json:"poe-standard"`
	PoePortMode string `json:"poe-port-mode"`
	FgtPeerPortName string `json:"fgt-peer-port-name"`
	FgtPeerDeviceName string `json:"fgt-peer-device-name"`
	IslLocalTrunkName string `json:"isl-trunk-name"`
	IslPeerPortName string `json:"isl-peer-port-name"`
	IslPeerDeviceName string `json:"isl-peer-device-name"`
	IslPeerDeviceSn string `json:"isl-peer-device-sn"`
	NativeVlan		string `json:"vlan"`
	AllowedVlansAll string `json:"allowed-vlans-all"`
	AllowedVlans	[]AllowedVlan `json:"allowed-vlans"`
	Type string `json:"type"`
	AccessMode string `json:"access-mode"`
	DhcpSnooping string `json:"dhcp-snooping"`
	StpState string `json:"stp-state"`
	StpRootGuard string `json:"stp-root-guard"`
	StpBpduGuard string `json:"stp-bpdu-guard"`
	EdgePort string `json:"edge-port"`
	LoopGuard string `json:"loop-guard"`
	LldpProfile string `json:"lldp-profile"`
	MacAddr string `json:"mac-addr"`
}

type AllowedVlan struct {
	VlanName string `json:"vlan-name"`
}

var pullCmd = &cobra.Command{
	Use: "pull",
	Short: "Pulls data from the chosen FortiGate/FortiSwitch",
	Long: `Pulls the data from the chosen FortiGate/FortiSwitch. Application only
focuses on pulling port information.

Will output to console if -o flag isn't provided. CSV will be generated in
the current directory if a full/relative path isn't provided.`,
	Run: func(cmd *cobra.Command, args []string) {
		if firewall {
			if name != "" {
				url, api_key := searchFortiGateAuthInfo(name)

				globalData = verifyFortiGateConnection(url, api_key, name)

				if strings.ToUpper(globalData.Results.Hostname) == strings.ToUpper(name) {

					switchManagerData = getFortiSwitchPortInfo(url, api_key)
					
					if fileName != "" {
						if typeCsv {
							fmt.Println("[i] Generating CSV file...")
							exportCsv(fileName, switchManagerData)
							fmt.Println("[i] CSV file generated.")
						}
						
					}

				}

			}

		}
	},
}

func init() {
	pullCmd.Flags().BoolVarP(&firewall, "firewall", "f", false, "Connects via FortiGate API")
	pullCmd.Flags().StringVarP(&name, "name", "n", "", "Configuration name of the firewall data will be pulled from.")
	pullCmd.Flags().StringVarP(&fileName, "output", "o", "", "Output file for the port map")
	pullCmd.Flags().BoolVarP(&typeCsv, "csv", "", false, "Indicates output file will be a CSV. Default is console.")

	rootCmd.AddCommand(pullCmd)
}

func searchFortiGateAuthInfo(name string) (host_url string, api_key string) {
	nameUpper := strings.ToUpper(name)

	for _, host := range config.Hosts {
		hostUpper := strings.ToUpper(host.Name)
		
		if hostUpper == nameUpper {
			host_url = host.Url
			api_key = host.ApiKey
		}
	}
	return
}

func verifyFortiGateConnection(url string, api_key string, inputName string) (gr GlobalApiReponse) {
	targetUrl := fmt.Sprintf("%s/api/v2/cmdb/system/global", url)
	authHeader := fmt.Sprintf("Bearer %s", api_key)
	
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", targetUrl, nil)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}

	req.Header.Add("Authorization", authHeader)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read API response! \n\nData: %v", err)
	}

	if err := json.Unmarshal(body, &gr); err != nil {
		fmt.Printf("Failed to read API response body! \n\nData: %v", err)
	}

	if gr.Results.Hostname == strings.ToUpper(inputName) {
		return
	}

	return gr
}

func getFortiSwitchPortInfo(url string, api_key string) (smr SwitchManagerApiReponse) {
	targetUrl := fmt.Sprintf("%s/api/v2/cmdb/switch-controller/managed-switch/", url)
	authHeader := fmt.Sprintf("Bearer %s", api_key)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", targetUrl, nil)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}

	req.Header.Add("Authorization", authHeader)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("Failed with status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Failed to read API response! \n\nData: %v", err)
	}

	if err := json.Unmarshal(body, &smr); err != nil {
		fmt.Printf("Failed to read API response body! \n\nData: %v", err)
	}

	return smr
}

func exportCsv(file string, ports SwitchManagerApiReponse) {

	var name string
	var header []string
	var lines  [][]string

	header = []string{"Switch", "Port", "Status", "POE Status", "Fiber", "Media Type", 
		"FortiGate Name", "FortiGate Port", "Switch Peer Name", "Switch Peer Name", 
		"Native VLAN", "Allowed VLANs", "STP Enabled", "STP Root Guard", "STP BPDU Guard", 
		"Edge Port", "Loop Guard", "LLDP Profile"}

	for _, result := range ports.Results {
		for _, port := range result.Ports {
			line := []string{port.SwitchId, port.PortName, port.Status, port.PoeStatus, strconv.Itoa(port.FiberPort), 
				port.MediaType, port.FgtPeerDeviceName, port.FgtPeerPortName, port.IslPeerDeviceName, port.IslPeerPortName,
				port.NativeVlan}
			
			tempSlice := []string {}
			for _, avlan := range port.AllowedVlans {
				tempSlice = append(tempSlice, avlan.VlanName)	
			}

			line = append(line, strings.Join(tempSlice, " "))

			lineUpdate := []string{port.StpState, port.StpRootGuard, port.StpBpduGuard,
				port.EdgePort, port.LoopGuard, port.LldpProfile}

			for _, l := range lineUpdate {
				line = append(line, l)
			}
			
			lines = append(lines, line)
		}
	}

	fext := path.Ext(file)

	if fext != "" {
		name = fmt.Sprintf("%s", file)
	}

	if fext == "" {
		name = fmt.Sprintf("%s.csv", file)
	}

	f, err := os.Create(name)
	if err != nil {
		fmt.Println(err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	w.Write(header)

	defer w.Flush()

	for _, line := range lines {
		err := w.Write(line)
		if err != nil {
			fmt.Println(err)
		}
	}

}
