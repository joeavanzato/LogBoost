package tldparser

import "strings"

func ParseDomain(dom string) (string, string, string) {
	var sub, main, tld string
	var s1, s2 string
	var mtype int
	tm := tldMap["ICANN DOMAINS"]
	for i := len(dom) - 1; i >= -1; i-- {
		if i == -1 || dom[i] == '.' {
			if i >= 0 {
				s1 = dom[:i]
			} else {
				s1 = ""
			}
			s2 = dom[i+1:]
			if _, ok := tm[s2]; ok || mtype == 2 {
				if ok {
					mtype = tm[s2]
				} else {
					mtype = 1
				}
				if mtype == 0 {
					continue
				}
				if mtype == 3 {
					break
				}

				tld = s2
				p := strings.LastIndexByte(s1, '.')
				if p >= 0 {
					sub = s1[:p]
					main = s1[p+1:]
				} else {
					sub = ""
					main = s1
				}
			} else {
				break
			}
		}
	}
	return sub, main, tld
}

func ParseDomainFldSld(sub, main, tld string) (fld string, sld1 string, sld2 string) {
	if main != "" {
		fld = main + "." + tld
		if sub != "" {
			p := strings.LastIndex(sub, ".")
			sld1 = sub[p+1:] + "." + fld
			if p >= 0 {
				p = strings.LastIndex(sub[:p], ".")
				sld2 = sub[p+1:] + "." + fld
			}
		}
	}
	return
}
