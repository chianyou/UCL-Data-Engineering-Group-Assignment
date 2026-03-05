-- Q1: Daily trend of newly published CVEs
SELECT
  published_date,
  new_cve_count
FROM agg_daily_new_cves
ORDER BY published_date;

-- Q2: CVSS severity distribution
SELECT
  cvss_severity,
  cve_count
FROM agg_cvss_severity_distribution
ORDER BY cve_count DESC;

-- Q3: KEV hit rate by CVSS severity
SELECT
  cvss_severity,
  total_cves,
  kev_cves,
  kev_hit_rate
FROM agg_kev_hit_rate_by_cvss_severity
ORDER BY kev_hit_rate DESC, total_cves DESC;

-- Q4: Top vendor/product groups by average EPSS score (minimum sample size)
SELECT
  vendor,
  product,
  total_cves,
  scored_cves,
  high_epss_cves,
  high_epss_rate,
  avg_epss_score
FROM agg_epss_by_vendor_product
WHERE scored_cves >= 5
ORDER BY avg_epss_score DESC
LIMIT 20;

-- Q5: Top CWE + vendor + product groups by CVE count
SELECT
  cwe_id,
  vendor,
  product,
  cve_count,
  kev_cves,
  kev_hit_rate,
  avg_epss_score
FROM agg_cwe_vendor_product
WHERE cwe_id <> ''
ORDER BY cve_count DESC
LIMIT 20;

-- Q6: Priority bucket distribution from the star-schema fact table
SELECT
  priority_bucket,
  COUNT(*) AS cve_count
FROM fact_vulnerability_risk
GROUP BY priority_bucket
ORDER BY cve_count DESC;

-- Q7: Monthly CVE publication trend using the date dimension
SELECT
  d.year,
  d.month,
  COUNT(*) AS published_cves
FROM fact_vulnerability_risk f
JOIN dim_date d
  ON f.published_date_key = d.date_key
GROUP BY d.year, d.month
ORDER BY d.year, d.month;

-- Q8: KEV vs non-KEV average EPSS and CVSS comparison
SELECT
  kev_flag,
  COUNT(*) AS cves,
  AVG(cvss_base_score) AS avg_cvss_base_score,
  AVG(epss_score) AS avg_epss_score
FROM fact_vulnerability_risk
GROUP BY kev_flag
ORDER BY kev_flag DESC;
