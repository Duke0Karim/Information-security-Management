#!/bin/bash

LOG_FILE="apache_logs"

echo "=== Apache Log Analysis ==="

# 1. Request Counts
total_requests=$(wc -l < "$LOG_FILE")
get_requests=$(grep -c "\"GET" "$LOG_FILE")
post_requests=$(grep -c "\"POST" "$LOG_FILE")

echo -e "\n1. Request Counts:"
echo "Total Requests: $total_requests"
echo "GET Requests: $get_requests"
echo "POST Requests: $post_requests"

# 2. Unique IP Addresses
echo -e "\n2. Unique IP Addresses:"
awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr > ip_counts.txt
total_unique_ips=$(wc -l < ip_counts.txt)
echo "Total Unique IPs: $total_unique_ips"
echo -e "IP-wise GET/POST counts:"
awk '
{
    ip = $1
    method = "-"
    match($0, /"[^"]+"/, request)
    if (request[0] ~ /GET/) method = "GET"
    else if (request[0] ~ /POST/) method = "POST"
    print ip, method
}' "$LOG_FILE" | sort | uniq -c | sort -nr | awk '{print $2, $3, $1}' | column -t

# 3. Failure Requests
echo -e "\n3. Failure Requests:"
failures=$(awk '$9 ~ /^4|^5/ {count++} END {print count}' "$LOG_FILE")
fail_pct=$(awk -v fail="$failures" -v total="$total_requests" 'BEGIN { printf("%.2f", (fail/total)*100) }')
echo "Failed Requests (4xx/5xx): $failures"
echo "Failure Percentage: $fail_pct%"

# 4. Top User
echo -e "\n4. Top User:"
head -n 1 ip_counts.txt | awk '{print "Most Active IP: " $2 " with " $1 " requests"}'

# 5. Daily Request Averages
echo -e "\n5. Daily Request Averages:"
days=$(awk -F: '{print $1}' "$LOG_FILE" | cut -d "[" -f2 | uniq | wc -l)
avg_requests=$(awk -v total="$total_requests" -v days="$days" 'BEGIN { printf("%.2f", total/days) }')
echo "Average Requests Per Day: $avg_requests"

# 6. Failure Analysis by Day
echo -e "\n6. Failure Analysis:"
awk '$9 ~ /^4|^5/ {
    split($4, datetime, ":")
    day = substr(datetime[1], 2)
    failures_by_day[day]++
}
END {
    for (d in failures_by_day)
        print d, failures_by_day[d]
}' "$LOG_FILE" | sort | column -t

# 7. Request by Hour
echo -e "\n7. Requests by Hour:"
awk -F: '{print $2}' "$LOG_FILE" | cut -d "[" -f2 | sort | uniq -c | awk '{printf("Hour %02d: %s requests\n", $2, $1)}'

# 8. Request Trends (hourly trends with analysis)
echo -e "\n8. Request Trends by Hour:"
# Extract hourly request counts and store in a temporary file
awk -F: '{print $2}' "$LOG_FILE" | cut -d "[" -f2 | sort | uniq -c | awk '{printf("%02d %s\n", $2, $1)}' | sort -n > hourly_counts.txt

# Display hourly counts
echo "Hourly Request Counts:"
cat hourly_counts.txt | awk '{printf("Hour %s: %s requests\n", $1, $2)}'

# Analyze trends
echo -e "\nTrend Analysis:"
awk '
BEGIN {
    prev_count = 0;
    prev_hour = -1;
    increasing = 0;
    decreasing = 0;
    max_count = 0;
    max_hour = "";
    min_count = 99999999;
    min_hour = "";
}
{
    hour = $1;
    count = $2;
    # Track max and min
    if (count > max_count) { max_count = count; max_hour = hour; }
    if (count < min_count) { min_count = count; min_hour = hour; }
    # Compare with previous hour for trends
    if (prev_hour != -1) {
        if (count > prev_count) {
            if (increasing == 0 || last_trend != "increase") {
                printf("Increasing from Hour %02d to %02d: %s to %s requests\n", prev_hour, hour, prev_count, count);
            }
            increasing++;
            last_trend = "increase";
        } else if (count < prev_count) {
            if (decreasing == 0 || last_trend != "decrease") {
                printf("Decreasing from Hour %02d to %02d: %s to %s requests\n", prev_hour, hour, prev_count, count);
            }
            decreasing++;
            last_trend = "decrease";
        }
    }
    prev_count = count;
    prev_hour = hour;
}
END {
    # Summary of trends
    printf("\nSummary:\n");
    printf("- Peak Hour: %s with %s requests\n", max_hour, max_count);
    printf("- Quietest Hour: %s with %s requests\n", min_hour, min_count);
    if (increasing > 0) {
        printf("- Noted %d instances of increasing request counts between consecutive hours\n", increasing);
    }
    if (decreasing > 0) {
        printf("- Noted %d instances of decreasing request counts between consecutive hours\n", decreasing);
    }
    if (increasing > decreasing) {
        printf("- Overall trend: Requests tend to increase more frequently than decrease.\n");
    } else if (decreasing > increasing) {
        printf("- Overall trend: Requests tend to decrease more frequently than increase.\n");
    } else {
        printf("- Overall trend: Balanced increases and decreases in request counts.\n");
    }
}' hourly_counts.txt

# Clean up temporary file
rm hourly_counts.txt

# 9. Status Code Breakdown
echo -e "\n9. Status Codes Breakdown:"
awk '{print $9}' "$LOG_FILE" | sort | grep -E "^[1-5][0-9]{2}$" | uniq -c | sort -nr | awk '{print "Status " $2 ": " $1 " times"}'

# 10. Most Active User by Method
echo -e "\n10. Most Active User by Method:"
echo "GET:"
grep "\"GET" "$LOG_FILE" | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 1
echo "POST:"
grep "\"POST" "$LOG_FILE" | awk '{print $1}' | sort | uniq -c | sort -nr | head -n 1

# 11. Patterns in Failure Requests
echo -e "\n11. Patterns in Failure Requests (By Day and Hour):"
awk '$9 ~ /^4|^5/ {
    split($4, dt, ":")
    day = substr(dt[1], 2)
    hour = dt[2]
    failures[day " " hour]++
}
END {
    for (key in failures)
        print key, failures[key]
}' "$LOG_FILE" | sort | column -t

# 12. Tailored Suggestions based on analysis
echo -e "\n=== Analysis Suggestions ==="
echo "- Monitor IP 66.249.73.135 (482 GET requests) for potential abuse or crawling. Check user-agent and requested resources to confirm if it's a legitimate bot or malicious; apply rate limiting if needed."
echo "- Address 213 404 errors and 2 403 errors (2.20% failure rate). Analyze URLs causing 404s for broken links and verify access controls for 403s to ensure legitimate users aren't blocked."
echo "- Investigate 3 500 errors to identify server-side issues (e.g., app bugs, resource exhaustion). Review logs for root causes and set up monitoring to catch 5xx errors quickly."
echo "- Analyze high failure days (18/May/2015 and 19/May/2015, 66 each) and hourly spikes (e.g., 15 failures at 09:00 on 20/May/2015). Check server load and requests to optimize resources or scale capacity."
echo "- Verify POST activity from 78.173.140.106 (3 of 5 total POSTs). Ensure these are legitimate (e.g., form submissions) and not attacks. Add validation or CAPTCHA if suspicious."
echo "- Handle peak traffic hours (14:00–20:00, e.g., 498 requests at 14:00). Ensure server capacity and consider caching or a CDN to reduce load during these times."
echo "- With 10,000 requests and 1,753 unique IPs, implement log rotation and consider centralized logging for easier analysis and monitoring as traffic grows."
echo "- Check high-activity IPs like 46.105.14.53 (364 GETs) and 130.237.218.86 (357 GETs) for legitimacy. Use tools like fail2ban or a WAF to limit excessive requests if needed."

echo -e "\n=== End of Report ==="
