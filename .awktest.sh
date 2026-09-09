sg_invoked_scripts() {
  printf '%s\n' "$1" | awk '
    function base(p,   a, n) { n = split(p, a, "/"); return a[n] }
    {
      s = $0
      gsub(/&&|\|\|/, ";", s)
      n = split(s, seg, /[;&|()\n]/)
      for (i = 1; i <= n; i++) {
        c = seg[i]
        while (match(c, /^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*|sudo|env|exec|time|nohup)([[:space:]]+|$)/))
          c = substr(c, RSTART + RLENGTH)
        nf = split(c, w, /[[:space:]]+/)
        k = 0
        for (j = 1; j <= nf; j++) if (w[j] != "") { k = j; break }
        if (k == 0) continue
        b = base(w[k])
        if (b ~ /^(ba|z|k|da)?sh$/ || w[k] == "source" || w[k] == ".") {
          skip = 0
          for (j = k + 1; j <= nf; j++) {
            if (w[j] == "") continue
            if (w[j] ~ /^-[A-Za-z]*n/) break
            if (w[j] == "-o" || w[j] == "-c") { skip = 1; continue }
            if (skip) { skip = 0; continue }
            if (w[j] ~ /^-/) continue
            print w[j]; break
          }
        } else if (w[k] ~ /^(\.\.?\/|\/|~\/)/) print w[k]
      }
    }' 2>/dev/null | sort -u
}
