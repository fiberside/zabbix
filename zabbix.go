package zabbix

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
)

/**
Zabbix and Go's RPC implementations don't play with each other.. at all.
So I've re-created the wheel at bit.
*/
type JsonRPCResponse struct {
	Jsonrpc string      `json:"jsonrpc"`
	Error   ZabbixError `json:"error"`
	Result  interface{} `json:"result"`
	Id      int         `json:"id"`
}

type JsonRPCRequest struct {
	Jsonrpc string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`

	// Zabbix 2.0:
	// The "user.login" method must be called without the "auth" parameter
	Auth string `json:"auth,omitempty"`
	Id   int    `json:"id"`
}

type ZabbixError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (z *ZabbixError) Error() string {
	return z.Data
}

type ZabbixHost struct {
	HostID        string          `json:"hostid"`
	Host          string          `json:"host"`
	Available     ZabbixJSONInt   `json:"available,omitempty"`
	Description   string          `json:"description,omitempty"`
	DisableUntil  ZabbixJSONInt64 `json:"disable_until,omitempty"`
	Error         string          `json:"error,omitempty"`
	ErrorsFrom    ZabbixJSONInt64 `json:"errors_from,omitempty"`
	Flags         ZabbixJSONInt   `json:"flags,omitempty"`
	InventoryMode ZabbixJSONInt   `json:"inventory_mode,omitempty"`

	IPMIAuthType     ZabbixJSONInt   `json:"ipmi_authtype,omitempty"`
	IPMIAvailable    ZabbixJSONInt   `json:"ipmi_available,omitempty"`
	IPMIDisableUntil ZabbixJSONInt64 `json:"ipmi_disable_until,omitempty"`
	IPMIError        string          `json:"ipmi_error,omitempty"`
	IPMIErrorsFrom   ZabbixJSONInt64 `json:"ipmi_errors_from,omitempty"`
	IPMIPassword     string          `json:"ipmi_password,omitempty"`
	IPMIPrivilege    ZabbixJSONInt   `json:"ipmi_privilege,omitempty"`
	IPMIUsername     string          `json:"ipmi_username,omitempty"`

	JmxAvailable    ZabbixJSONInt   `json:"jmx_available,omitempty"`
	JmxDisableUntil ZabbixJSONInt64 `json:"jmx_disable_until,omitempty"`
	JmxError        string          `json:"jmx_error,omitempty"`
	JmxErrorsFrom   ZabbixJSONInt64 `json:"jmx_errors_from,omitempty"`

	MaintenanceFrom   ZabbixJSONInt64 `json:"maintenance_from,omitempty"`
	MaintenanceStatus ZabbixJSONInt   `json:"maintenance_status,omitempty"`
	MaintenanceType   ZabbixJSONInt   `json:"maintenance_type,omitempty"`
	MaintenanceID     string          `json:"maintenanceid,omitempty"`

	Name        string `json:"name,omitempty"`
	ProxyHostID string `json:"proxy_hostid,omitempty"`

	SNMPAvailable    ZabbixJSONInt   `json:"snmp_available"`
	SNMPDisableUntil ZabbixJSONInt64 `json:"snmp_disable_until,omitempty"`
	SNMPError        string          `json:"snmp_error,omitempty"`
	SNMPErrorsFrom   ZabbixJSONInt64 `json:"snmp_errors_from,omitempty"`

	Status ZabbixJSONInt `json:"status,omitempty"`

	TLSIssuer      string `json:"tls_issuer,omitempty"`
	TLSSubject     string `json:"tls_subject,omitempty"`
	TLSPskIdentity string `json:"tls_psk_identity,omitempty"`
	TLSPsk         string `json:"tls_psk,omitempty"`
	TLSConnect     string `json:"tls_connect,omitempty"`
	TLSAccept      string `json:"tls_accept,omitempty"`

	LastAccess ZabbixJSONInt64 `json:"lastaccess,omitempty"`
	TemplateID string          `json:"templateid,omitempty"`

	Groups          []ZabbixGroup          `json:"groups,omitempty"`
	Applications    []ZabbixApplication    `json:"applications,omitempty"`
	Discoveries     []ZabbixDiscovery      `json:"discoveries,omitempty"`
	DiscoveryRule   ZabbixDiscoveryRule    `json:"discoveryRule,omitempty"`
	Graphs          []ZabbixGraph          `json:"graphs,omitempty"`
	HostDiscovery   []ZabbixHostDiscovery  `json:"hostDiscovery,omitempty"`
	HTTPTests       []ZabbixHTTPTest       `json:"httpTests,omitempty"`
	Interfaces      []ZabbixInterface      `json:"interfaces,omitempty"`
	Inventory       ZabbixInventory        `json:"inventory,omitempty"`
	Items           []ZabbixItem           `json:"items,omitempty"`
	Macros          []ZabbixMacros         `json:"macros,omitempty"`
	ParentTemplates []ZabbixParentTemplate `json:"parentTemplates,omitempty"`
	Screens         []ZabbixScreen         `json:"screens,omitempty"`
	Triggers        []ZabbixTrigger        `json:"triggers,omitempty"`
}

type ZabbixGraph map[string]interface{}
type ZabbixGraphItem map[string]interface{}

type ZabbixGroup struct {
	Groupid  string `json:"groupid"`
	Name     string `json:"name"`
	Flags    ZabbixJSONInt `json:"flags,omitempty"`
	Internal string `json:"internal"`
}

type ZabbixDiscovery map[string]interface{}
type ZabbixHostDiscovery map[string]interface{}
type ZabbixHTTPTest map[string]interface{}
type ZabbixInventory map[string]interface{}
type ZabbixMacros map[string]interface{}
type ZabbixParentTemplate map[string]interface{}
type ZabbixScreen map[string]interface{}

type ZabbixJSONInt int
type ZabbixJSONInt64 int64
type ZabbixJSONFloat32 float32

func (fi *ZabbixJSONInt) UnmarshalJSON(b []byte) error {
	if b[0] != '"' {
		return json.Unmarshal(b, (*int)(fi))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*fi = ZabbixJSONInt(i)
	return nil
}

func (fi *ZabbixJSONInt64) UnmarshalJSON(b []byte) error {
	if b[0] != '"' {
		return json.Unmarshal(b, (*int64)(fi))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	i, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*fi = ZabbixJSONInt64(i)
	return nil
}

func (fi *ZabbixJSONFloat32) UnmarshalJSON(b []byte) error {
	if b[0] != '"' {
		return json.Unmarshal(b, (*float32)(fi))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}

	i, err := strconv.ParseFloat(s, 32)

	if err != nil {
		return err
	}
	*fi = ZabbixJSONFloat32(i)
	return nil
}

type ZabbixInterface struct {
	InterfaceID string        `json:"interfaceid"`
	DNS         string        `json:"dns"`
	HostID      string        `json:"hostid"`
	IP          string        `json:"ip"`
	Main        ZabbixJSONInt `json:"main"`
	Port        string        `json:"port"`
	Type        ZabbixJSONInt `json:"type"`
	UseIP       ZabbixJSONInt `json:"useip"`
	Bulk        ZabbixJSONInt `json:"bulk,omitempty"`
}

type ZabbixTrigger struct {
	TriggerID   string `json:"triggerid"`
	Description string `json:"description"`
	Expression  string `json:"expression"`

	Comments           string          `json:"comments,omitempty"`
	Flags              ZabbixJSONInt   `json:"flags,omitempty"`
	LastChange         ZabbixJSONInt64 `json:"lastchange,omitempty"`
	Priority           ZabbixJSONInt   `json:"priority,omitempty"`
	State              ZabbixJSONInt   `json:"state,omitempty"`
	Status             ZabbixJSONInt   `json:"status,omitempty"`
	TemplateID         string          `json:"templateid,omitempty"`
	Type               ZabbixJSONInt   `json:"type,omitempty"`
	URL                string          `json:"url,omitempty"`
	Value              ZabbixJSONInt   `json:"value,omitempty"`
	RecoveryMode       ZabbixJSONInt   `json:"recovery_mode,omitempty"`
	RecoveryExpression string          `json:"recovery_expression,omitempty"`
	CorrelationMode    ZabbixJSONInt   `json:"correlation_mode,omitempty"`
	CorrelationTag     string          `json:"correlation_tag,omitempty"`
	ManualClose        ZabbixJSONInt   `json:"manual_close,omitempty"`
	Error              string          `json:"error,omitempty"`
}

type ZabbixApplication map[string]interface{}
type ZabbixDiscoveryRule map[string]interface{}
type ZabbixItemDiscovery map[string]interface{}
type ZabbixPreprocessing map[string]interface{}

type ZabbixHistoryItem struct {
	Clock  string `json:"clock"`
	Value  string `json:"value"`
	Itemid string `json:"itemid"`
}

type ZabbixItem struct {
	ItemID      string `json:"itemid"`
	Delay       string `json:"delay"`
	HostID      string `json:"hostid"`
	InterfaceID string `json:"interfaceid"`
	Key         string `json:"key_"`
	Name        string `json:"name"`

	Type                 ZabbixJSONInt   `json:"type"`
	ValueType            ZabbixJSONInt   `json:"value_type"`
	AuthType             ZabbixJSONInt   `json:"authtype,omitempty"`
	Description          string          `json:"description,omitempty"`
	Error                string          `json:"error,omitempty"`
	Flags                ZabbixJSONInt   `json:"flags,omitempty"`
	History              string          `json:"history,omitempty"`
	InventoryLink        ZabbixJSONInt   `json:"inventory_link,omitempty"`
	IPMISensor           string          `json:"ipmi_sensor,omitempty"`
	LastClock            ZabbixJSONInt64 `json:"lastclock,omitempty"`
	LastNs               ZabbixJSONInt   `json:"lastns,omitempty"`
	LastValue            string          `json:"lastvalue,omitempty"`
	LogTimeFmt           string          `json:"logtimefmt,omitempty"`
	MTime                ZabbixJSONInt64 `json:"mtime,omitempty"`
	Params               string          `json:"params,omitempty"`
	Password             string          `json:"password,omitempty"`
	Port                 string          `json:"port,omitempty"`
	PrevValue            string          `json:"prevvalue,omitempty"`
	PrivateKey           string          `json:"privatekey,omitempty"`
	PublicKey            string          `json:"publickey,omitempty"`
	SNMPCommunity        string          `json:"snmp_community,omitempty"`
	SNMPOID              string          `json:"snmp_oid,omitempty"`
	SNMPv3AuthPassPhrase string          `json:"snmpv3_authpassphrase,omitempty"`
	SNMPv3AuthProtocol   ZabbixJSONInt   `json:"snmpv3_authprotocol,omitempty"`
	SNMPv3ContextName    string          `json:"snmpv3_contextname,omitempty"`
	SNMPv3PrivPassPhrase string          `json:"snmpv3_privpassphrase,omitempty"`
	SNMPv3PrivProtocol   ZabbixJSONInt   `json:"snmpv3_privprotocol,omitempty"`
	SNMPv3SecurityLevel  ZabbixJSONInt   `json:"snmpv3_securitylevel,omitempty"`
	SNMPv3SecurityName   string          `json:"snmpv3_securityname,omitempty"`
	State                ZabbixJSONInt   `json:"state,omitempty"`
	Status               ZabbixJSONInt   `json:"status,omitempty"`
	TemplateID           string          `json:"templateid,omitempty"`
	TrapperHosts         string          `json:"trapper_hosts"`
	Trends               string          `json:"trends,omitempty"`
	Units                string          `json:"units,omitempty"`
	Username             string          `json:"username,omitempty"`
	ValueMapID           string          `json:"valuemapid,omitempty"`
	JmxEndpoint          string          `json:"jmx_endpoint"`
	MasterItemID         ZabbixJSONInt   `json:"master_itemid,omitempty"`

	DataType    ZabbixJSONInt     `json:"data_type,omitempty"`
	DelayFlex   string            `json:"delay_flex,omitempty"`
	Delta       string            `json:"delta,omitempty"`
	Formula     ZabbixJSONFloat32 `json:"formula,omitempty"`
	Multiplier  ZabbixJSONInt     `json:"multiplier,omitempty"`
	LastLogSize string            `json:"lastlogsize,omitempty"`
	LifeTime    string            `json:"lifetime,omitempty"`
	EvalType    string            `json:"evaltype,omitempty"`

	Hosts         []ZabbixHost          `json:"hosts,omitempty"`
	Interfaces    []ZabbixInterface     `json:"interfaces,omitempty"`
	Triggers      []ZabbixTrigger       `json:"triggers,omitempty"`
	Applications  []ZabbixApplication   `json:"applications,omitempty"`
	DiscoveryRule ZabbixDiscoveryRule   `json:"discoveryRule,omitempty"`
	ItemDiscovery []ZabbixItemDiscovery `json:"itemDiscovery,omitempty"`
	Processing    []ZabbixPreprocessing `json:"preprocessing,omitempty"`
}

type API struct {
	url    string
	user   string
	passwd string
	id     int
	auth   string
	Client *http.Client
}

func GetFields(i interface{}) []string {

	fields := []string{}

	t := reflect.TypeOf(i)
	if t.Kind() == reflect.Struct {
		// Iterate over all available fields and read the tag value
		for i := 0; i < t.NumField(); i++ {

			field := t.Field(i)

			switch field.Type.Kind() {
			case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64, reflect.String:

				tag := field.Tag.Get("json")
				parts := strings.Split(strings.TrimSpace(tag), ",")
				fields = append(fields, parts[0])

			}
		}
	}
	return fields
}

func NewAPI(server, user, passwd string) (*API, error) {
	return &API{server, user, passwd, 0, "", &http.Client{}}, nil
}

func (api *API) GetAuth() string {
	return api.auth
}

/**
Each request establishes its own connection to the server. This makes it easy
to keep request/responses in order without doing any concurrency
*/

func (api *API) ZabbixRequest(method string, data interface{}) (JsonRPCResponse, error) {
	// Setup our JSONRPC Request data
	id := api.id
	api.id = api.id + 1
	jsonobj := JsonRPCRequest{"2.0", method, data, api.auth, id}
	encoded, err := json.Marshal(jsonobj)

	if err != nil {
		return JsonRPCResponse{}, err
	}

	// Setup our HTTP request
	request, err := http.NewRequest("POST", api.url, bytes.NewBuffer(encoded))
	if err != nil {
		return JsonRPCResponse{}, err
	}
	request.Header.Add("Content-Type", "application/json-rpc")
	if api.auth != "" {
		// XXX Not required in practice, check spec
		//request.SetBasicAuth(api.user, api.passwd)
		//request.Header.Add("Authorization", api.auth)
	}

	// Execute the request
	response, err := api.Client.Do(request)
	if err != nil {
		return JsonRPCResponse{}, err
	}

	/**
	We can't rely on response.ContentLength because it will
	be set at -1 for large responses that are chunked. So
	we treat each API response as streamed data.
	*/
	var result JsonRPCResponse
	var buf bytes.Buffer

	_, err = io.Copy(&buf, response.Body)
	if err != nil {
		return JsonRPCResponse{}, err
	}

	json.Unmarshal(buf.Bytes(), &result)

	response.Body.Close()

	return result, nil
}

func (api *API) Login() (bool, error) {
	params := make(map[string]string, 0)
	params["user"] = api.user
	params["password"] = api.passwd

	response, err := api.ZabbixRequest("user.login", params)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return false, err
	}

	if response.Error.Code != 0 {
		return false, &response.Error
	}

	api.auth = response.Result.(string)
	return true, nil
}

func (api *API) Logout() (bool, error) {
	emptyparams := make(map[string]string, 0)
	response, err := api.ZabbixRequest("user.logout", emptyparams)
	if err != nil {
		return false, err
	}

	if response.Error.Code != 0 {
		return false, &response.Error
	}

	return true, nil
}

func (api *API) Version() (string, error) {
	response, err := api.ZabbixRequest("APIInfo.version", make(map[string]string, 0))
	if err != nil {
		return "", err
	}

	if response.Error.Code != 0 {
		return "", &response.Error
	}

	return response.Result.(string), nil
}

/**
Interface to the user.* calls
*/
func (api *API) User(method string, data interface{}) ([]interface{}, error) {
	response, err := api.ZabbixRequest("user."+method, data)
	if err != nil {
		return nil, err
	}

	if response.Error.Code != 0 {
		return nil, &response.Error
	}

	return response.Result.([]interface{}), nil
}

/**
Interface to the host.* calls
*/
func (api *API) Host(method string, data interface{}) ([]ZabbixHost, error) {
	response, err := api.ZabbixRequest("host."+method, data)
	if err != nil {
		return nil, err
	}

	if response.Error.Code != 0 {
		return nil, &response.Error
	}
	//fmt.Print(data)
	// XXX uhg... there has got to be a better way to convert the response
	// to the type I want to return
	res, err := json.Marshal(response.Result)
	var ret []ZabbixHost
	err = json.Unmarshal(res, &ret)
	//fmt.Print(err)
	return ret, nil
}

/**
Interface to the graph.* calls
*/
func (api *API) Graph(method string, data interface{}) ([]ZabbixGraph, error) {
	response, err := api.ZabbixRequest("graph."+method, data)
	if err != nil {
		return nil, err
	}

	if response.Error.Code != 0 {
		return nil, &response.Error
	}

	// XXX uhg... there has got to be a better way to convert the response
	// to the type I want to return
	res, err := json.Marshal(response.Result)
	var ret []ZabbixGraph
	err = json.Unmarshal(res, &ret)
	return ret, nil
}

/**
Interface to the history.* calls
*/
func (api *API) History(method string, data interface{}) ([]ZabbixHistoryItem, error) {
	response, err := api.ZabbixRequest("history."+method, data)
	if err != nil {
		return nil, err
	}

	if response.Error.Code != 0 {
		return nil, &response.Error
	}

	// XXX uhg... there has got to be a better way to convert the response
	// to the type I want to return
	res, err := json.Marshal(response.Result)
	var ret []ZabbixHistoryItem
	err = json.Unmarshal(res, &ret)
	return ret, nil
}

/**
Interface to the item.* calls
*/
func (api *API) Item(method string, data interface{}) ([]ZabbixItem, error) {
	response, err := api.ZabbixRequest("item."+method, data)
	if err != nil {
		return nil, err
	}

	if response.Error.Code != 0 {
		return nil, &response.Error
	}

	// XXX uhg... there has got to be a better way to convert the response
	// to the type I want to return
	res, err := json.Marshal(response.Result)
	var ret []ZabbixItem
	err = json.Unmarshal(res, &ret)

	return ret, nil
}

/**
Interface to the hostgroup.* calls
*/
func (api *API) HostGroup(method string, data interface{}) ([]ZabbixGroup, error) {
	response, err := api.ZabbixRequest("hostgroup."+method, data)
	if err != nil {
		return nil, err
	}

	if response.Error.Code != 0 {
		return nil, &response.Error
	}

	// XXX uhg... there has got to be a better way to convert the response
	// to the type I want to return
	res, err := json.Marshal(response.Result)
	var ret []ZabbixGroup
	err = json.Unmarshal(res, &ret)

	return ret, nil
}
