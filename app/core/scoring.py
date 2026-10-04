def score(base,corroboration=0,asset_risk=0): return max(0,min(100,base+corroboration+asset_risk))
def severity(v): return "critical" if v>=80 else "high" if v>=60 else "medium" if v>=35 else "low"
