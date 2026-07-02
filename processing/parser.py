import pandas as pd

def parse_volatility_txt(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()

    cleaned_lines = [
        line.rstrip("\n") for line in lines
        if line.strip() and not line.startswith("Volatility 3 Framework")
    ]

    if not cleaned_lines:
        return pd.DataFrame()

    header = cleaned_lines[0].split("\t")
    header = [h.strip() for h in header]
    rows = []

    for line in cleaned_lines[1:]:
        fields = line.split("\t")
        fields = [f.strip() for f in fields]
        if len(fields) < len(header):
            fields += [""] * (len(header) - len(fields))
        rows.append(fields[:len(header)])

    df = pd.DataFrame(rows, columns=header)
    return df


def load_all_outputs(base_path="processing/sample_output"):
    data = {
        "pslist": parse_volatility_txt(f"{base_path}/pslist.txt"),
        "netscan": parse_volatility_txt(f"{base_path}/netscan.txt"),
        "cmdline": parse_volatility_txt(f"{base_path}/cmdline.txt"),
        "dlllist": parse_volatility_txt(f"{base_path}/dlllist.txt"),
    }
    return data


if __name__ == "__main__":
    datasets = load_all_outputs()

    for name, df in datasets.items():
        print(f"\n=== {name.upper()} ===")
        print(f"Rows: {len(df)}, Columns: {list(df.columns)}")
        print(df.head(3))
