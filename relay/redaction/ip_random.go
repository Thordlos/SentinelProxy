package redaction

import (
	"math/rand"
	"net"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// ipClassification 表示 IP 地址的分类
type ipClassification int

const (
	ipClassPrivateA ipClassification = iota // 10.0.0.0/8
	ipClassPrivateB                         // 172.16.0.0/12
	ipClassPrivateC                         // 192.168.0.0/16
	ipClassLoopback                         // 127.0.0.0/8
	ipClassLinkLocal                        // 169.254.0.0/16
	ipClassMulticast                        // 224.0.0.0/4
	ipClassPublic                           // 公网地址
)

// classifyIP 对 IPv4 地址进行分类
func classifyIP(ip net.IP) ipClassification {
	if ip == nil {
		return ipClassPublic
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return ipClassPublic
	}

	// 回环地址 127.0.0.0/8
	if ip4[0] == 127 {
		return ipClassLoopback
	}
	// 链路本地 169.254.0.0/16
	if ip4[0] == 169 && ip4[1] == 254 {
		return ipClassLinkLocal
	}
	// 组播 224.0.0.0/4
	if ip4[0] >= 224 && ip4[0] <= 239 {
		return ipClassMulticast
	}
	// 私有 A 类 10.0.0.0/8
	if ip4[0] == 10 {
		return ipClassPrivateA
	}
	// 私有 B 类 172.16.0.0/12
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return ipClassPrivateB
	}
	// 私有 C 类 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return ipClassPrivateC
	}

	return ipClassPublic
}

// isPrivateIP 判断 IP 是否为 RFC 1918 私有地址
func isPrivateIP(ip net.IP) bool {
	class := classifyIP(ip)
	return class == ipClassPrivateA || class == ipClassPrivateB || class == ipClassPrivateC
}

// generatePrivateIP 生成随机私有 IP
// crossClass=true 时允许跨 A/B/C 类随机选择
func generatePrivateIP(crossClass bool, exclude map[string]bool) string {
	var a, b, c, d int

	classRoll := rand.Intn(3) // 0=A, 1=B, 2=C
	if !crossClass {
		classRoll = -1 // 由调用方通过 maskBytes 控制
	}

	// 如果不跨类，classRoll 会被 maskBytes 覆盖，这里默认生成 A 类
	switch classRoll {
	case 0:
		a, b, c, d = 10, rand.Intn(256), rand.Intn(256), rand.Intn(254)+1
	case 1:
		a, b, c, d = 172, rand.Intn(16)+16, rand.Intn(256), rand.Intn(254)+1
	default:
		a, b, c, d = 192, 168, rand.Intn(256), rand.Intn(254)+1
	}

	return net.IPv4(byte(a), byte(b), byte(c), byte(d)).String()
}

// generatePublicIP 生成随机公网 IP，排除所有保留范围
func generatePublicIP(preserveBits int, origBytes []byte, exclude map[string]bool) string {
	for attempts := 0; attempts < 200; attempts++ {
		var a, b, c, d int

		if preserveBits > 0 && origBytes != nil {
			// 保留前 N 位，只随机化剩余部分
			if preserveBits <= 8 {
				a = int(origBytes[0])
				b = rand.Intn(256)
				c = rand.Intn(256)
				d = rand.Intn(254) + 1
			} else if preserveBits <= 16 {
				a = int(origBytes[0])
				b = int(origBytes[1])
				c = rand.Intn(256)
				d = rand.Intn(254) + 1
			} else {
				a = int(origBytes[0])
				b = int(origBytes[1])
				c = int(origBytes[2])
				d = rand.Intn(254) + 1
			}
		} else {
			a = rand.Intn(223) + 1 // 排除 0.x 和 224+ (组播/E类)
			b = rand.Intn(256)
			c = rand.Intn(256)
			d = rand.Intn(254) + 1
		}

		ip := net.IPv4(byte(a), byte(b), byte(c), byte(d))
		class := classifyIP(ip)

		if class == ipClassPublic && !exclude[ip.String()] {
			return ip.String()
		}
	}

	// fallback: 返回一个不可能是冲突的公网 IP
	return "203.0.113.1" // TEST-NET-3 (RFC 5737) 文档保留地址
}

// RandomizeIP 对 IP 地址进行格式保持随机化
// 会话一致性由 state.ForwardIP 保证，还原由 MaskedInverse 保证
func RandomizeIP(originalIP string, state *MaskingState, op OperatorConfig) string {
	if originalIP == "" || state == nil {
		return originalIP
	}

	// 会话一致性：相同原 IP 返回相同假 IP
	if fakeIP := state.GetForwardIP(originalIP); fakeIP != "" {
		return fakeIP
	}

	ip := net.ParseIP(originalIP)
	if ip == nil {
		return originalIP
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return originalIP
	}

	isPrivate := isPrivateIP(ip4)

	// 配置参数，带默认值
	preserveScope := true
	crossClass := true
	preserveBits := op.IPRandomPreserveBits
	if preserveBits < 0 {
		preserveBits = 0
	}
	if preserveBits > 24 {
		preserveBits = 24
	}

	// 构建冲突排除集合
	exclude := make(map[string]bool)
	for orig, fake := range state.ForwardIP {
		exclude[fake] = true
		exclude[orig] = true // 避免假 IP 等于某个原始 IP
	}
	exclude[originalIP] = true

	var fakeIP string
	for attempts := 0; attempts < 200; attempts++ {
		if isPrivate {
			// 私有地址 → 随机私有地址
			fakeIP = generatePrivateIP(crossClass, exclude)
		} else {
			// 公网地址 → 随机公网地址
			origBytes := []byte(ip4)
			fakeIP = generatePublicIP(preserveBits, origBytes, exclude)
		}

		if fakeIP == "" || exclude[fakeIP] {
			continue
		}

		// 验证 preserveScope：公私域不变
		if preserveScope {
			fakeParsed := net.ParseIP(fakeIP)
			if fakeParsed != nil {
				fakeIsPrivate := isPrivateIP(fakeParsed)
				if isPrivate != fakeIsPrivate {
					continue
				}
			}
		}

		exclude[fakeIP] = true
		break
	}

	if fakeIP == "" {
		// 兜底：极端情况下使用 Marker 标记
		fakeIP = MarkerStart + "IP_FAILED" + MarkerEnd
	}

	// 存储映射（ForwardIP 保证会话一致性，MaskedInverse 保证可还原）
	state.SetForwardIP(originalIP, fakeIP)
	state.SetMaskedMapping(fakeIP, originalIP)

	return fakeIP
}
