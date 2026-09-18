package auth

import (
	"crypto/rand"
	"math/big"

	utls "github.com/refraction-networking/utls"
)

// ==================== Codex rustls TLS 指纹 ====================
//
// 真实 Codex CLI 是 Rust 二进制（codex-rs），HTTP 栈为 reqwest + rustls，
// crypto provider 为 aws-lc-rs（codex-rs utils/rustls-provider 强制安装）。
// 本文件的 ClientHelloSpec 取自对 codex 同栈探针（reqwest 0.12 +
// rustls 0.23.45 + aws_lc_rs）的真实抓包，逐字段对齐。
//
// 与 Chrome/Node.js/Go 指纹的关键差异（风控常检项）：
//   - 无 GREASE（rustls 不发，Chrome 发）
//   - 扩展集合 {SNI, status_request, supported_groups, point_formats,
//     signature_algorithms, ALPN, EMS, session_ticket, supported_versions,
//     psk_modes, key_share} 与 rustls 完全一致
//   - 扩展顺序：rustls 0.23.31+ 每次握手用 order_seed 随机打乱
//     （rustls 源码 msgs/handshake.rs order_insensitive_extensions_in_random_order），
//     因此本 spec 也在每次构造时洗牌，任何固定顺序反而会被统计识别
//   - cipher list 末尾带 0x00FF（TLS_EMPTY_RENEGOTIATION_INFO_SCSV）
//
// 与抓包真身（aws_lc_rs provider）的唯一刻意偏差：supported_groups 不含
// X25519MLKEM768(0x11EC)。aws_lc_rs 会声明该曲线但 key_share 只发 X25519，
// 支持 MLKEM 的对端（Cloudflare）因此回 HelloRetryRequest 索取 MLKEM share，
// 而 uTLS 无法应答该 HRR，握手必断。去掉 4588 后形态等价于 rustls+ring
// provider（ring 本就不支持 MLKEM）——这是真实存在且常见的 rustls 客户端家族，
// 且对 CF 恒免 HRR（一次握手完成）。
//
// ⚠️ rustls 版本升级可能改变这些参数（如新增曲线/扩展）。bump 时重新抓包核对。

// CodexRustlsClientHelloSpec 返回与真实 codex（rustls+aws_lc_rs）一致的 ClientHello。
// 每次调用构造新实例并随机打乱扩展顺序（对齐 rustls 的 per-handshake order_seed
// 随机化）：uTLS 握手过程也会就地改写扩展内容（如 key_share 密钥），不可复用实例。
func CodexRustlsClientHelloSpec() *utls.ClientHelloSpec {
	extensions := []utls.TLSExtension{
		&utls.SNIExtension{},                             // 0
		&utls.StatusRequestExtension{},                   // 5
		&utls.SupportedCurvesExtension{Curves: []utls.CurveID{ // 10
			utls.X25519,    // 29
			utls.CurveP256, // 23
			utls.CurveP384, // 24
			// 不含 X25519MLKEM768：见文件头注释（uTLS 无法应答 MLKEM HRR，
			// 当前形态等价于 rustls+ring provider）。
		}},
		&utls.SupportedPointsExtension{SupportedPoints: []byte{0x00}}, // 11
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{ // 13
			0x0503, // ecdsa_secp384r1_sha384
			0x0403, // ecdsa_secp256r1_sha256
			0x0603, // ecdsa_secp521r1_sha512
			0x0807, // ed25519
			0x0806, // rsa_pss_rsae_sha512
			0x0805, // rsa_pss_rsae_sha384
			0x0804, // rsa_pss_rsae_sha256
			0x0601, // rsa_pkcs1_sha512
			0x0501, // rsa_pkcs1_sha384
			0x0401, // rsa_pkcs1_sha256
			0x0904, // rsa_pss_pss_sha256
			0x0905, // rsa_pss_pss_sha384
			0x0906, // rsa_pss_pss_sha512
		}},
		&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}, // 16
		&utls.ExtendedMasterSecretExtension{},                          // 23
		&utls.SessionTicketExtension{},                                 // 35
		&utls.SupportedVersionsExtension{Versions: []uint16{            // 43
			0x0304, // TLS 1.3
			0x0303, // TLS 1.2
		}},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{1}}, // 45 psk_dhe_ke
		&utls.KeyShareExtension{KeyShares: []utls.KeyShare{   // 51
			// Data 留空由 uTLS 握手时生成真实密钥（>1 字节会被当作预设密钥原样发送）。
			{Group: utls.X25519},
		}},
	}
	shuffleTLSExtensions(extensions)
	// pre_shared_key 固定末尾且不参与洗牌：TLS 1.3 要求它在最后（rustls 同样
	// 钉在末尾）。配合 Config.OmitEmptyPsk，全新握手（无缓存会话）时该扩展
	// 不上线，线与此前逐字节一致；命中会话缓存时携带真实 binder 复用会话，
	// 与 rustls 的 resumption 行为一致。
	extensions = append(extensions, &utls.UtlsPreSharedKeyExtension{})
	return &utls.ClientHelloSpec{
		// 0x0302 0x0301 0x0303 = TLS1.3 AES-256-GCM / AES-128-GCM / CHACHA20
		// （aws_lc_rs 默认顺序，AES-256 在前，与 ring 不同）；随后 ECDHE 系；
		// 0x00FF 是 renegotiation SCSV，rustls 固定附带。
		CipherSuites: []uint16{
			0x1302, // TLS_AES_256_GCM_SHA384
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
			0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
			0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
			0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
			0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		},
		CompressionMethods: []byte{0x00},
		Extensions:         extensions,
	}
}

// shuffleTLSExtensions 就地洗牌扩展顺序（Fisher-Yates，crypto/rand）。
// 对齐 rustls 的 per-handshake 扩展随机化；洗牌失败（rand 不可用）时保持原序，
// 任何顺序都是真实 rustls 可达的合法序列。
func shuffleTLSExtensions(extensions []utls.TLSExtension) {
	for i := len(extensions) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return
		}
		j := int(n.Int64())
		extensions[i], extensions[j] = extensions[j], extensions[i]
	}
}
