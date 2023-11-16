package certificate

import (
	"context"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"gitlab.example.com/zhangweijie/component/middlerware/schemas"
	toolModels "gitlab.example.com/zhangweijie/tool-sdk/models"
	"net/http"
	"strconv"
	"strings"
)

type Issuer struct {
	Country            []string `json:"IssuerCountry"`            // 国家
	Organization       []string `json:"IssuerOrganization"`       // 组织
	OrganizationalUnit []string `json:"IssuerOrganizationalUnit"` // 组织单位
	SerialNumber       string   `json:"IssuerSerialNumber"`       // 序列号
	CommonName         string   `json:"IssuerCommonName"`
}

type Subject struct {
	Country            []string `json:"SubjectCountry"`            // 国家
	Organization       []string `json:"SubjectOrganization"`       // 组织
	OrganizationalUnit []string `json:"SubjectOrganizationalUnit"` // 组织单位
	SerialNumber       string   `json:"SubjectSerialNumber"`       // 序列号
	CommonName         string   `json:"SubjectCommonName"`
}

type Validity struct {
	NotBefore string // 颁发时间
	NotAfter  string // 截止时间
}

type Certificate struct {
	Issuer                         // 颁发者
	Subject                        // 主题
	Validity                       // 有效期
	Version               string   `json:"Version"`               // 版本号
	SerialNumber          string   `json:"SerialNumber"`          // 序列号
	Signature             string   `json:"Signature"`             // 证书签名
	SignatureAlgorithm    string   `json:"SignatureAlgorithm"`    // 证书签名算法
	PublicKey             string   `json:"PublicKey"`             // 公钥
	PublicKeyAlgorithm    string   `json:"PublicKeyAlgorithm"`    // 签名算法
	AuthorityKeyId        string   `json:"AuthorityKeyId"`        // 颁发者密钥标识符
	BasicConstraintsValid bool     `json:"BasicConstraintsValid"` // 基本限制
	IsCA                  bool     `json:"IsCA"`                  // 证书是否是一个证书授权者（Certificate Authority，CA）
	CRLDistributionPoints []string `json:"CRLDistributionPoints"` // CRL 分发点
	MaxPathLen            int      `json:"MaxPathLen"`            // 证书链中从当前证书到根证书的最大路径长度,它限制了可以使用当前证书作为中间 CA 的最大深度。如果某个证书的 MaxPathLen 值为0，则该证书不能用作中间 CA。
	MaxPathLenZero        bool     `json:"MaxPathLenZero"`        // 该字段存在，并且其值为 true，那么它表示当前证书的 MaxPathLen 属性将被忽略，即使该证书是中间 CA
	OCSPServer            []string `json:"OCSPServer"`            // 用于在线证书状态协议（Online Certificate Status Protocol，OCSP）查询的服务器的网址
	IssuingCertificateURL []string `json:"IssuingCertificateURL"` // 指定签发者（颁发者）证书的下载地址
	KeyUsage              int      `json:"KeyUsage"`              // 密钥用途
	ExtKeyUsage           []int    `json:"ExtKeyUsage"`           // 增强密钥用途
	SubjectKeyId          string   `json:"SubjectKeyId"`          // 标识证书的主体（Subject）
	DNSNames              []string `json:"DNSNames"`              // 指定证书所关联的主机名（域名）
	MD5Finger             string   `json:"MD5Finger"`             // MD5 指纹
	SHA1Finger            string   `json:"SHA1Finger"`            // SHA1 指纹
	SHA256Finger          string   `json:"SHA256Finger"`          // SHA256指纹
}

func splitByN(s string, n int) []string {
	var parts []string
	for len(s) > 0 {
		if len(s) < n {
			parts = append(parts, strings.ToUpper(s))
			break
		}
		parts = append(parts, strings.ToUpper(s[:n]))
		s = s[n:]
	}
	return parts
}

func GetCertInfoOfUrl(ctx context.Context, work *toolModels.Work, validParams *schemas.CertificateTaskCreateSchema) (*Certificate, error) {
	certificate := &Certificate{}
	// 创建一个 HTTP 客户端
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// 发起 GET 请求
	resp, err := client.Get(validParams.Url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 获取证书信息
	state := resp.TLS
	if state != nil {
		cert := state.PeerCertificates[0]
		// 计算 SHA-1 指纹
		certificate.SHA1Finger = strings.Join(splitByN(fmt.Sprintf("%x", sha1.Sum(cert.Raw)), 2), ":")
		// 计算 SHA-256 指纹
		certificate.SHA256Finger = strings.Join(splitByN(fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), 2), ":")
		// 计算 MD5 指纹
		certificate.MD5Finger = strings.Join(splitByN(fmt.Sprintf("%x", md5.Sum(cert.Raw)), 2), ":")
		certificate.Version = strconv.Itoa(cert.Version)
		serialNumber := strings.Join(splitByN(fmt.Sprintf("%x", cert.SerialNumber.Bytes()), 2), ":")
		certificate.SerialNumber = serialNumber
		signature := strings.Join(splitByN(fmt.Sprintf("%x", cert.Signature), 2), ":")
		certificate.Signature = signature
		certificate.SignatureAlgorithm = cert.SignatureAlgorithm.String()
		// ISSUER
		certificate.Issuer.Country = cert.Issuer.Country
		certificate.Issuer.Organization = cert.Issuer.Organization
		certificate.Issuer.OrganizationalUnit = cert.Issuer.OrganizationalUnit
		certificate.Issuer.SerialNumber = cert.Issuer.SerialNumber
		certificate.Issuer.CommonName = cert.Issuer.CommonName
		// SUBJECT
		certificate.Subject.Country = cert.Subject.Country
		certificate.Subject.Organization = cert.Subject.Organization
		certificate.Subject.OrganizationalUnit = cert.Subject.OrganizationalUnit
		certificate.Subject.SerialNumber = cert.Subject.SerialNumber
		certificate.Subject.CommonName = cert.Subject.CommonName
		// Validity
		certificate.Validity.NotBefore = cert.NotBefore.String()
		certificate.Validity.NotAfter = cert.NotAfter.String()
		publicKey := cert.PublicKey
		switch publicKey := publicKey.(type) {
		case *rsa.PublicKey:
			certificate.PublicKey = strings.Join(splitByN(fmt.Sprintf("%x", publicKey.N.Bytes()), 2), ":")
		}
		certificate.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
		authorityKeyId := strings.Join(splitByN(fmt.Sprintf("%x", cert.AuthorityKeyId), 2), ":")
		certificate.AuthorityKeyId = authorityKeyId
		certificate.BasicConstraintsValid = cert.BasicConstraintsValid
		certificate.IsCA = cert.IsCA
		certificate.CRLDistributionPoints = cert.CRLDistributionPoints
		certificate.MaxPathLen = cert.MaxPathLen
		certificate.MaxPathLenZero = cert.MaxPathLenZero
		certificate.OCSPServer = cert.OCSPServer
		certificate.IssuingCertificateURL = cert.IssuingCertificateURL
		subjectKeyId := strings.Join(splitByN(fmt.Sprintf("%x", cert.SubjectKeyId), 2), ":")
		certificate.SubjectKeyId = subjectKeyId
		certificate.DNSNames = cert.DNSNames
	}

	return certificate, err
}

func GetCertInfoOfResponse(response *http.Response) *Certificate {
	certificate := &Certificate{}

	// 获取证书信息
	state := response.TLS
	if state != nil {
		cert := state.PeerCertificates[0]
		// 计算 SHA-1 指纹
		certificate.SHA1Finger = strings.Join(splitByN(fmt.Sprintf("%x", sha1.Sum(cert.Raw)), 2), ":")
		// 计算 SHA-256 指纹
		certificate.SHA256Finger = strings.Join(splitByN(fmt.Sprintf("%x", sha256.Sum256(cert.Raw)), 2), ":")
		// 计算 MD5 指纹
		certificate.MD5Finger = strings.Join(splitByN(fmt.Sprintf("%x", md5.Sum(cert.Raw)), 2), ":")
		certificate.Version = strconv.Itoa(cert.Version)
		serialNumber := strings.Join(splitByN(fmt.Sprintf("%x", cert.SerialNumber.Bytes()), 2), ":")
		certificate.SerialNumber = serialNumber
		signature := strings.Join(splitByN(fmt.Sprintf("%x", cert.Signature), 2), ":")
		certificate.Signature = signature
		certificate.SignatureAlgorithm = cert.SignatureAlgorithm.String()
		// ISSUER
		certificate.Issuer.Country = cert.Issuer.Country
		certificate.Issuer.Organization = cert.Issuer.Organization
		certificate.Issuer.OrganizationalUnit = cert.Issuer.OrganizationalUnit
		certificate.Issuer.SerialNumber = cert.Issuer.SerialNumber
		certificate.Issuer.CommonName = cert.Issuer.CommonName
		// SUBJECT
		certificate.Subject.Country = cert.Subject.Country
		certificate.Subject.Organization = cert.Subject.Organization
		certificate.Subject.OrganizationalUnit = cert.Subject.OrganizationalUnit
		certificate.Subject.SerialNumber = cert.Subject.SerialNumber
		certificate.Subject.CommonName = cert.Subject.CommonName
		// Validity
		certificate.Validity.NotBefore = cert.NotBefore.String()
		certificate.Validity.NotAfter = cert.NotAfter.String()
		publicKey := cert.PublicKey
		switch publicKey := publicKey.(type) {
		case *rsa.PublicKey:
			modulus := strings.Join(splitByN(fmt.Sprintf("%x", publicKey.N.Bytes()), 2), ":")
			certificate.PublicKey = modulus
		}
		certificate.PublicKeyAlgorithm = cert.PublicKeyAlgorithm.String()
		authorityKeyId := strings.Join(splitByN(fmt.Sprintf("%x", cert.AuthorityKeyId), 2), ":")
		certificate.AuthorityKeyId = authorityKeyId
		certificate.BasicConstraintsValid = cert.BasicConstraintsValid
		certificate.IsCA = cert.IsCA
		certificate.CRLDistributionPoints = cert.CRLDistributionPoints
		certificate.MaxPathLen = cert.MaxPathLen
		certificate.MaxPathLenZero = cert.MaxPathLenZero
		certificate.OCSPServer = cert.OCSPServer
		certificate.IssuingCertificateURL = cert.IssuingCertificateURL
		subjectKeyId := strings.Join(splitByN(fmt.Sprintf("%x", cert.SubjectKeyId), 2), ":")
		certificate.SubjectKeyId = subjectKeyId
		certificate.DNSNames = cert.DNSNames
	}

	return certificate
}
