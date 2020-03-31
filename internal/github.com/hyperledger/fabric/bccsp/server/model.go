package server

type hbcaSignData struct {
	SignData []byte
	CertID   string
}

// ResponseWSDL ResponseWSDL
type ResponseWSDL struct {
	Code    string `json:"errorCode"`
	Message string `json:"errorMsg"`
	Data    string `json:"data"`
}

// HBCAApplyInput input info
type HBCAApplyInput struct {
	CreditCode           string `json:"creditCode"`           // 统一社会信用代码
	UnitName             string `json:"unitName"`             // 单位名称
	UnitAddress          string `json:"unitAddress"`          // 单位地址
	LegalName            string `json:"legalName"`            // 法人姓名
	LegalID              string `json:"legalID"`              // 法人公民身份号码
	LegalPhone           string `json:"legalPhone"`           // 法人手机号码
	ProvinceCode         string `json:"provinceCode"`         // 省市区编码
	PrefecturalLevelCity string `json:"prefecturalLevelCity"` // 地级市(中文)
	Stproperty           string `json:"STProperty"`           // 证书ST属性值如：湖北省
	UnitProperty         string `json:"unitProperty"`         // 证书OU属性值：机关单位/事业/企业（中文）
	Location             string `json:"location"`             // 省市区6位编码
	ESID                 string `json:"esID"`                 // 印章唯一赋码
	P10                  string `json:"p10"`                  // 签名证书申请CSR内容，base64编码
	DoubleP10            string `json:"doubleP10"`            // 加密证书CSR内容，base64编码。可以与签名证书一样，加密证书的密钥对最终由KMC生成
	AuthUserID           string `json:"authUserId"`           // 授权用户ID，由湖北CA提供
	PlatformName         string `json:"platformName"`         // 申请平台名称，由印章平台提供
	CertDn               string `json:"certDn"`               // 申请平台名称，由印章平台提供
}

// ExtendCertInput extend cert input
type ExtendCertInput struct {
	CaData       *RefCode `json:"caData"`       // 申请证书接口返回的所有数据
	ESID         string   `json:"esID"`         // 印章的esid
	BeginTime    string   `json:"beginTime"`    // 证书生效时间，格式：20151204011850622
	EndTime      string   `json:"endTime"`      // 证书失效时间，格式：20161204011850622
	MonthTime    string   `json:"monthTime"`    // 续期多少个月
	P10          string   `json:"p10"`          // 申请证书CSR文件，与申请证书接口的p10保持一致，base64编码
	DoubleP10    string   `json:"doubleP10"`    // 申请证书CSR文件，与申请证书接口的p10保持一致，base64编码
	AuthUserID   string   `json:"authUserId"`   // 授权用户ID，由湖北CA提供
	PlatformName string   `json:"platformName"` // 申请平台名称，由印章平台提供
	CertDn       string   `json:"certDn"`       // 申请平台名称，由印章平台提供
}

// CertRevokeInput revoke cert input
type CertRevokeInput struct {
	CaData       *RefCode `json:"caData"`       // 申请证书接口返回的所有数据
	RevokeDesc   string   `json:"revokeDesc"`   // 注销原因
	AuthUserID   string   `json:"authUserId"`   // 授权用户ID，由湖北CA提供
	PlatformName string   `json:"platformName"` // 申请平台名称，由印章平台提供
	CertDn       string   `json:"certDn"`       // 申请平台名称，由印章平台提供
}

// ImportSignCert import sign cert
type ImportSignCert struct {
	CertID       string `json:"certId,omitempty"`
	CertName     string `json:"certName,omitempty"`
	SignCertB64  string `json:"signCertB64,omitempty"`
	CertType     string `json:"certType,omitempty"`
	RootCertName string `json:"rootCertName,omitempty"`
	ImportType   string `json:"importType,omitempty"`
	Password     string `json:"password,omitempty"`
}

// ImportEncCert import enc cert
type ImportEncCert struct {
	RootID          string `json:"rootId,omitempty"`
	SignCertID      string `json:"signCertId,omitempty"`
	EncCertID       string `json:"encCertId,omitempty"`
	EncCertB64      string `json:"encCertB64,omitempty"`
	DoubleEncPriKey string `json:"doubleEncPriKey,omitempty"`
	CertType        string `json:"certType,omitempty"`
}

// CreateP10Input input parameter
type CreateP10Input struct {
	CertID     string `json:"certId,omitempty"`
	CertName   string `json:"certName,omitempty"`
	ApplyDn    string `json:"applyDn,omitempty"`
	EncryptAlg string `json:"encryptAlg,omitempty"`
	KeyLength  string `json:"keyLength,omitempty"`
	DigestAlg  string `json:"digestAlg,omitempty"`
}

// ResponseCA response result
type ResponseCA struct {
	Status  string               `json:"status"`
	Message string               `json:"message"`
	Data    *ResponseApplyCAInfo `json:"data"`
}

// ResponseApplyCAInfo ca info
type ResponseApplyCAInfo struct {
	SignatureCert             string `json:"signatureCert"`
	EncryptCert               string `json:"encryptCert"`
	P7b                       string `json:"p7b"`
	DoubleP7b                 string `json:"doubleP7b"`
	DoubleEncryptedPrivateKey string `json:"doubleEncryptedPrivateKey"`
	RefCode                   string `json:"refCode"`
}

// RefCode ref code
type RefCode struct {
	RefCode string `json:"refCode"`
}
