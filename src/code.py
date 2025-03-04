import pyshark
import pandas as pd
import collections
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

import os
from scapy.all import *
# הגדרת נתיב לתיקיית res בשולחן העבודה של המשתמש
desktop_path = os.path.expanduser("~/Desktop/res")  # לינוקס
# אם התיקייה נמצאת במקום אחר, יש לעדכן את הנתיב ידנית

# 🟢 הגדרת קבצי PCAP של 5 אפליקציות
pcap_files = {
    "Chrome": "chrome_record.pcapng",
    "FireFox": "firefox_record.pcapng",
    "Spotify": "spotify_record.pcapng",
    "YouTube": "youtube_record.pcapng",
    "Zoom": "zoom_record.pcapng"
}

# צבעים קבועים לכל אפליקציה
app_colors = {
    "Chrome": "#1f77b4",  # כחול
    "FireFox": "#ff7f0e",  # כתום
    "Spotify": "#2ca02c",  # ירוק
    "YouTube": "#d62728",  # אדום
    "Zoom": "#9467bd"  # סגול
}

# מילון שבו נאחסן את כל ה־packets של כל אפליקציה (במקום לקרוא כל קובץ שוב ושוב)
all_packets = {}

##########################################
# קריאה אחת לכל קובץ – ושמירה במילון
##########################################
for app, file_path in pcap_files.items():
    cap = pyshark.FileCapture(
        file_path,
        use_json=False,
        custom_parameters=['-n'],  # ביטול name resolution
        include_raw=False
    )
    cap.load_packets()  # טוען את כל החבילות לזיכרון
    all_packets[app] = list(cap)  # שומר רשימת Packet-ים
    cap.close()

##########################################
# משתנים לאיסוף הנתונים (כמו בקוד המקורי)
##########################################
ttl_values = collections.defaultdict(list)
ihl_values = collections.defaultdict(list)
tls_counts = collections.defaultdict(int)
packet_sizes = collections.defaultdict(list)

tcp_flags = collections.defaultdict(lambda: collections.Counter())
protocol_counts = collections.defaultdict(lambda: collections.Counter())
traffic_direction = collections.defaultdict(lambda: {"incoming": 0, "outgoing": 0})
tcp_window_sizes = collections.defaultdict(list)

##########################################
# עיבוד כל המידע – הפעם רק מתוך all_packets
##########################################
for app in pcap_files.keys():
    for packet in all_packets[app]:
        try:
            ttl = int(packet.ip.ttl)
            ihl = int(packet.ip.hdr_len)
            size = int(packet.length)

            # הגדרת פרוטוקול אחד בלבד עבור החבילה
            protocol = "Unknown"

            if "TLS" in packet:
                protocol = "TLS"
                tls_counts[app] += 1
            elif 'QUIC' in packet:
                protocol = "QUIC"
            elif 'HTTP' in packet:
                protocol = "HTTP"
            elif 'RTP' in packet:
                protocol = "RTP"
            elif 'DNS' in packet:
                protocol = "DNS"
            elif hasattr(packet, 'transport_layer'):
                protocol = packet.transport_layer  # לרוב TCP או UDP

            protocol_counts[app][protocol] += 1

            ttl_values[app].append(ttl)
            ihl_values[app].append(ihl)
            packet_sizes[app].append(size)

            if "TCP" in packet:
                flags = packet.tcp.flags
                tcp_flags[app][flags] += 1
                tcp_window_sizes[app].append(int(packet.tcp.window_size_value))

            if packet.ip.src.startswith("192.168") or packet.ip.src.startswith("10."):
                traffic_direction[app]["outgoing"] += 1
            else:
                traffic_direction[app]["incoming"] += 1

        except AttributeError:
            pass

##########################################
# -- כאן נשאר כל קוד השרטוט המקורי --
##########################################

sns.set_theme(style="whitegrid")

# 1️⃣ *TTL Values*
ttl_avg = {app: np.mean(ttl_values[app]) for app in ttl_values}
plt.figure(figsize=(10, 8))
bars = plt.bar(ttl_avg.keys(), ttl_avg.values(), color=[app_colors[app] for app in ttl_avg.keys()])
plt.xlabel("Application", fontsize=12)
plt.ylabel("TTL Value", fontsize=12)
plt.title("Most Common TTL Values by Application", fontsize=14, fontweight="bold")
plt.xticks(rotation=45)
for bar in bars:
    plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{int(bar.get_height())}',
             ha='center', va='bottom', fontsize=10, fontweight="bold")
plt.show()

# 2️⃣ *IP Header Length*
ihl_avg = {app: np.mean(ihl_values[app]) for app in ihl_values}
plt.figure(figsize=(10, 8))
bars = plt.bar(ihl_avg.keys(), ihl_avg.values(), color=[app_colors[app] for app in ihl_avg.keys()])
plt.xlabel("Application", fontsize=12)
plt.ylabel("Header Size (bytes)", fontsize=12)
plt.title("IP Header Length by Application", fontsize=14, fontweight="bold")
plt.xticks(rotation=45)
for bar in bars:
    plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{int(bar.get_height())}',
             ha='center', va='bottom', fontsize=10, fontweight="bold")
plt.show()

# 3️⃣ *TLS Usage*
total_packets = {app: len(packet_sizes[app]) for app in packet_sizes}
tls_usage = {app: (tls_counts[app] / total_packets[app]) * 100 for app in tls_counts}
plt.figure(figsize=(10, 8))
bars = plt.bar(tls_usage.keys(), tls_usage.values(), color=[app_colors[app] for app in tls_usage.keys()])
plt.xlabel("Application", fontsize=12)
plt.ylabel("Percentage of TLS Packets (%)", fontsize=12)
plt.title("TLS Usage by Application", fontsize=14, fontweight="bold")
plt.xticks(rotation=45)
for bar in bars:
    plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{bar.get_height():.1f}%',
             ha='center', va='bottom', fontsize=10, fontweight="bold")
plt.show()

# 4️⃣ *Packet Size Distribution*
data = []
for app, sizes in packet_sizes.items():
    for size in sizes:
        data.append({"Application": app, "Packet Size (bytes)": size})

df_packets = pd.DataFrame(data)

plt.figure(figsize=(10, 6))
sns.boxplot(
    x="Application",
    y="Packet Size (bytes)",
    hue="Application",
    data=df_packets,
    showfliers=False,
    palette=app_colors
)
plt.ylim(0, df_packets["Packet Size (bytes)"].quantile(0.95))  # חותכים את ה-5% הגבוהים ביותר
plt.xlabel("Application", fontsize=12)
plt.ylabel("Packet Size (bytes)", fontsize=12)
plt.title("Packet Size Comparison by Application", fontsize=14, fontweight="bold")
plt.grid()
plt.show()

# 5️⃣ *Traffic Direction*
traffic_percent = {
    app: {
        "Incoming": (traffic_direction[app]["incoming"] / sum(traffic_direction[app].values())) * 100,
        "Outgoing": (traffic_direction[app]["outgoing"] / sum(traffic_direction[app].values())) * 100
    }
    for app in traffic_direction
}
df_traffic = pd.DataFrame(traffic_percent).T
df_traffic.plot(kind="bar", stacked=True, figsize=(10, 6), color=["steelblue", "orange"])
plt.xlabel("Application", fontsize=12)
plt.ylabel("Percentage of Packets (%)", fontsize=12)
plt.title("Traffic Direction by Application", fontsize=14, fontweight="bold")
plt.legend(title="Direction")
plt.xticks(rotation=45)
plt.show()

# 6️⃣ *TCP Window Size*
window_avg = {app: np.mean(tcp_window_sizes[app]) for app in tcp_window_sizes}
plt.figure(figsize=(10, 8))
bars = plt.bar(window_avg.keys(), window_avg.values(), color=[app_colors[app] for app in window_avg.keys()])
plt.xlabel("Application", fontsize=12)
plt.ylabel("Window Size (bytes)", fontsize=12)
plt.title("Average TCP Window Size by Application", fontsize=14, fontweight="bold")
plt.xticks(rotation=45)
for bar in bars:
    plt.text(bar.get_x() + bar.get_width() / 2, bar.get_height(), f'{int(bar.get_height())}',
             ha='center', va='bottom', fontsize=10, fontweight="bold")
plt.show()

#------------------------------------------------------------------------------------
# 7️⃣ *PROTOCOL DISTRIBUTION*
df_protocols = pd.DataFrame(protocol_counts).fillna(0)

print("🔍 כל הפרוטוקולים שנמצאו בכל אפליקציה:")
print(df_protocols)

df_protocols_percent = df_protocols.div(df_protocols.sum(axis=0), axis=1) * 100

plt.figure(figsize=(16, 10))
df_protocols_percent.T.plot(kind="bar", stacked=True, colormap="tab10", figsize=(16, 10))

for app_idx, app in enumerate(df_protocols_percent.columns):
    bottom_value = 0
    for proto_idx, proto in enumerate(df_protocols_percent.index):
        value = df_protocols_percent.loc[proto, app]
        if value > 1:
            plt.text(app_idx, bottom_value + value / 2, f"{value:.1f}%",
                     ha="center", fontsize=10, fontweight="bold")
        bottom_value += value

plt.xlabel("Application", fontsize=12)
plt.ylabel("Percentage of Packets (%)", fontsize=12)
plt.title("Protocol Distribution by Application (All Protocols)", fontsize=14, fontweight="bold")
plt.legend(title="Protocol", bbox_to_anchor=(1.05, 1), loc='upper left')
plt.xticks(rotation=45)
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.show()

plt.figure(figsize=(12, 6))
sns.histplot(
    df_packets,
    x="Packet Size (bytes)",
    hue="Application",
    element="step",
    common_norm=False,
    bins=100,
    palette=app_colors,
    multiple="layer",
    alpha=0.6
)
plt.axvline(x=60, color="red", linestyle="--", label="TCP ACK (~60B)")
plt.axvline(x=1400, color="blue", linestyle="--", label="MTU Limit (~1400B)")
plt.xscale("log")
plt.xlabel("Packet Size (bytes)", fontsize=12)
plt.ylabel("Frequency", fontsize=12)
plt.title("Packet Size Distribution by Application (Log Scale)", fontsize=14, fontweight="bold")
plt.legend(title="Application")
plt.grid()
plt.show()

#####################-------Flow Volume (Total Bytes Transmitted) by Application-------------------------------------------------------


df_flow = df_packets.groupby("Application")["Packet Size (bytes)"].sum().reset_index()

plt.figure(figsize=(10, 6))
sns.barplot(x="Application", y="Packet Size (bytes)", data=df_flow, palette="tab10")

for i, value in enumerate(df_flow["Packet Size (bytes)"]):
    plt.text(i, value + value * 0.02, f"{value:,}", ha="center", fontsize=10, fontweight="bold")

plt.xlabel("Application", fontsize=12)
plt.ylabel("Total Bytes Transmitted", fontsize=12)
plt.title("Flow Volume (Total Bytes Transmitted) by Application", fontsize=14, fontweight="bold")
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.show()


#-----------------------Flow Size (Total Number of Packets) by Application----------------------------------------------------
flow_size = {app: len(packet_sizes[app]) for app in packet_sizes}
df_flow_size = pd.DataFrame(flow_size.items(), columns=["Application", "Total Packets"])

plt.figure(figsize=(10, 6))
sns.barplot(x="Application", y="Total Packets", data=df_flow_size, palette="tab10")

for i, value in enumerate(df_flow_size["Total Packets"]):
    plt.text(i, value + value * 0.02, f"{value:,}", ha="center", fontsize=10, fontweight="bold")

plt.xlabel("Application", fontsize=12)
plt.ylabel("Total Packets", fontsize=12)
plt.title("Flow Size (Total Number of Packets) by Application", fontsize=14, fontweight="bold")
plt.grid(axis="y", linestyle="--", alpha=0.7)
plt.show()

#----------------------------------Flow Duration Distribution----------------------------------------------
from collections import defaultdict

flow_start_times = defaultdict(dict)
flow_end_times   = defaultdict(dict)
flow_lengths     = defaultdict(list)


# -- במקום זה, ננתח את הזרימות מתוך all_packets:
for app in pcap_files.keys():
    for packet in all_packets[app]:
        try:
            flow_key = (
                packet.ip.src,
                packet.ip.dst,
                packet[packet.transport_layer].srcport,
                packet[packet.transport_layer].dstport,
                packet.transport_layer
            )
            timestamp = float(packet.sniff_timestamp)

            if flow_key not in flow_start_times[app]:
                flow_start_times[app][flow_key] = timestamp
            flow_end_times[app][flow_key] = timestamp

            if packet.transport_layer == "TCP":
                if hasattr(packet.tcp, "flags_fin") or hasattr(packet.tcp, "flags_reset"):
                    flow_end_times[app][flow_key] = timestamp

        except AttributeError:
            continue

for app in flow_start_times.keys():
    for flow_key in flow_start_times[app]:
        duration = flow_end_times[app][flow_key] - flow_start_times[app][flow_key]
        if duration > 0:
            flow_lengths[app].append(duration)

for app in flow_lengths.keys():
    plt.figure(figsize=(10, 6))
    sns.histplot(flow_lengths[app], bins=50, kde=True, color=app_colors[app])
    plt.xlabel("Flow Duration (seconds)", fontsize=12)
    plt.ylabel("Frequency", fontsize=12)
    plt.title(f"Flow Duration Distribution - {app}", fontsize=14, fontweight="bold")
    plt.grid()
    plt.show()

# ------------------------------------------------------------------------------
# TCP flags
import pyshark

# מילון שממפה את הביטים לדגלים
BIT_TO_NAME = {
    0x01: "FIN",
    0x02: "SYN",
    0x04: "RST",
    0x08: "PSH",
    0x10: "ACK",
    0x20: "URG",
    0x40: "ECE",
    0x80: "CWR",
}

# הגדרה של קומבינציות שהיית רוצה לספור בנפרד
SPECIAL_COMBOS = [
    ({"ACK", "FIN"}, "ACK+FIN"),
    ({"ACK", "SYN"}, "ACK+SYN"),
    ({"ACK", "RST"}, "ACK+RST"),
    ({"ACK", "PSH"}, "ACK+PSH"),
]

tcp_flags_counts = collections.defaultdict(lambda: collections.Counter())

for app in pcap_files.keys():
    for packet in all_packets[app]:
        try:
            if "TCP" in packet:
                hex_value = packet.tcp.flags
                flags_int = int(hex_value, 16)

                flag_bits_list = []
                for bit_mask, flag_name in BIT_TO_NAME.items():
                    if flags_int & bit_mask:
                        flag_bits_list.append(flag_name)

                # אם אין כלום, נגדיר כ-NONE
                if not flag_bits_list:
                    flag_label = "NONE"
                else:
                    flag_set = set(flag_bits_list)

                    # נבדוק קודם אם יש התאמה לאחת הקומבינציות
                    for combo_set, combo_label in SPECIAL_COMBOS:
                        # אם כל הפריטים ב-combo_set קיימים ב-flag_set
                        if combo_set.issubset(flag_set):
                            flag_label = combo_label
                            break
                    else:
                        # לא נמצא combo מיוחד -> נחבר את כל הדגלים כרגיל
                        # אפשר למיין כדי לקבל סדר אחיד: flag_bits_list.sort()
                        flag_label = "+".join(sorted(flag_bits_list))

                tcp_flags_counts[app][flag_label] += 1

        except AttributeError:
            continue

# המרת הנתונים ל- DataFrame
df_tcp_flags = pd.DataFrame(tcp_flags_counts).fillna(0)

# חישוב אחוזים מכלל החבילות של כל אפליקציה
df_tcp_flags_percent = df_tcp_flags.div(df_tcp_flags.sum(axis=0), axis=1) * 100

# ציור הגרף
plt.figure(figsize=(22, 12))
df_tcp_flags_percent.T.plot(
    kind="barh",
    stacked=True,
    colormap="tab10",
    figsize=(22, 12)
)

# הוספת תוויות לכל עמודה מעל סף מסוים (כדי למנוע הצגת ערכים קטנים מדי)
for app_idx, app in enumerate(df_tcp_flags_percent.columns):
    right_value = 0
    for flag_idx, flag_label in enumerate(df_tcp_flags_percent.index):
        value = df_tcp_flags_percent.loc[flag_label, app]
        if value > 2:  # מציג רק אם מעל 2% מהתעבורה
            plt.text(right_value + value / 2, app_idx,
                     f"{value:.1f}%", ha="center",
                     fontsize=10, fontweight="bold")
        right_value += value

plt.xlabel("Percentage of TCP Packets (%)", fontsize=12)
plt.ylabel("TCP Flag", fontsize=12)
plt.title("TCP Flags Distribution by Application", fontsize=14, fontweight="bold")
plt.legend(title="Application", bbox_to_anchor=(1.05, 1), loc='upper left')
plt.grid(axis="x", linestyle="--", alpha=0.7)
plt.show()
# ---------------------------------------------------------packet size
sns.set_theme(style="darkgrid")

plt.figure(figsize=(14, 10))
sns.histplot(
    data=df_packets,
    x="Packet Size (bytes)",
    hue="Application",
    bins=100,  # כמות הבינים בהיסטוגרמה - אפשר להתאים
    multiple="layer",  # אפשר "stack", "dodge" או "layer"
    alpha=0.6  # שקיפות כדי לראות חפיפות
)

plt.title("Combined Packet Size Distribution", fontsize=14, fontweight="bold")
plt.xlabel("Packet Size (bytes)", fontsize=12)
plt.ylabel("Frequency", fontsize=12)

# אופציונלי: אם יש לך טווח רחב מאוד של גדלי חבילות, אפשר לעבור לסקאלה לוגריתמית:
# plt.xscale("log")

plt.legend(title="Application")
plt.grid(True, linestyle="--", alpha=0.7)
plt.show()

# ---------------------------------------------------------------------------
# arrival time
#


interarrival_data = []  # כאן ייאגר המידע

sorted_packets = {}  # מילון לאחסון התוצאות

for app in pcap_files.keys():
    print(f"🔍 עיבוד נתונים עבור: {app}")  # הדפסה לבדיקה - האם באמת עובר על כל האפליקציות?

    if app not in all_packets or not all_packets[app]:
        print(f"⚠ אין נתונים עבור {app}, מדלג...")
        continue  # דילוג על אפליקציות ריקות

    sorted_packets[app] = sorted(all_packets[app], key=lambda p: float(p.sniff_timestamp))

    prev_timestamp = None
    for packet in sorted_packets[app]:
        current_ts = float(packet.sniff_timestamp)
        if prev_timestamp is not None:
            # 2. חישוב הפרש (inter-arrival)
            diff = current_ts - prev_timestamp
            interarrival_data.append({"Application": app, "Inter-Arrival Time": diff})
        prev_timestamp = current_ts

# 3. בדיקה האם יש נתונים מכל האפליקציות
if not interarrival_data:
    print("❌ לא נמצאו נתוני inter-arrival, בדוק את all_packets!")
    exit()

# 4. בניית DataFrame
df_interarrival = pd.DataFrame(interarrival_data)

print("📊 נתונים לכל האפליקציות:", df_interarrival["Application"].unique())  # בדיקה שהכול מופיע

plt.figure(figsize=(12, 6))
sns.histplot(
    data=df_interarrival,
    x="Inter-Arrival Time",
    hue="Application",
    bins=100,  # כמות הבינים - אפשר לשנות לפי רצונך
    alpha=0.6,  # שקיפות לעזרה בהבחנה בחפיפות
    multiple="layer"  # או "stack"/"dodge" לפי העדפה
)

plt.title("Inter-Arrival Time Distribution Across Applications", fontsize=14, fontweight="bold")
plt.xlabel("Inter-Arrival Time (seconds)", fontsize=12)
plt.ylabel("Frequency", fontsize=12)

plt.grid(True, linestyle="--", alpha=0.7)
plt.legend(title="Application")
plt.show()


# --------------------------------------------------GAP----------




THRESHOLD = 3  # סף מינימלי לחבילות ב-bin
all_large_gaps = []  # כאן נצבור את כל הפערים

sorted_packets = {}  # מילון לאחסון התוצאות

for app in pcap_files.keys():
    print(f"🔍 עיבוד נתונים עבור: {app}")  # הדפסה לבדיקת ריצה על כל האפליקציות

    sorted_packets[app] = sorted(all_packets[app], key=lambda p: float(p.sniff_timestamp))

    # 2. בניית מילון bins_dict,
    bins_dict = collections.defaultdict(list)
    for packet in sorted_packets[app]:
        ts = float(packet.sniff_timestamp)
        second_bin = int(ts)  # עיגול כלפי מטה לשנייה שלמה
        bins_dict[second_bin].append(ts)

    # 3. בניית רשימת Bins תקינים
    valid_bins = []
    for bin_sec in sorted(bins_dict.keys()):
        timestamps = bins_dict[bin_sec]
        if len(timestamps) >= THRESHOLD:
            min_ts = min(timestamps)
            max_ts = max(timestamps)
            valid_bins.append((bin_sec, min_ts, max_ts))

    # 4. חישוב ה-"Large Gap":
    for i in range(len(valid_bins) - 1):
        current_bin_max = valid_bins[i][2]  # max_ts של bin הנוכחי
        next_bin_min = valid_bins[i + 1][1]  # min_ts של bin הבא
        gap = next_bin_min - current_bin_max

        # נשמור רק פערים חיוביים
        if gap > 0:
            all_large_gaps.append({
                "Application": app,
                "Large Gap (seconds)": gap
            })

# 5. הפיכת הפערים ל-DataFrame וציור היסטוגרמה
df_large_gaps = pd.DataFrame(all_large_gaps)
print(df_large_gaps.head())

# בדיקה אם יש נתונים מכל האפליקציות
print("📊 נתונים לכל האפליקציות:", df_large_gaps["Application"].unique())

sns.set_theme(style="darkgrid")
plt.figure(figsize=(10, 6))

sns.histplot(
    data=df_large_gaps,
    x="Large Gap (seconds)",
    hue="Application",
    bins=50,
    multiple="layer",
    alpha=0.7
)

plt.title("Large Gaps Distribution - Combined", fontsize=14, fontweight="bold")
plt.xlabel("Large Gaps (seconds)", fontsize=12)
plt.ylabel("Frequency", fontsize=12)
plt.grid(True, linestyle="--", alpha=0.5)
plt.legend(title="Application")
plt.show()
