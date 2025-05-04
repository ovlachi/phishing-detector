import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

def prepare_dataset(
    legitimate_path="data/raw/legitimate.csv",
    phishing_path="data/raw/phishing.csv",
    output_dir="data/processed",
    test_size=0.2,
    val_size=0.1,
    random_state=42
):
    """
    Prepare dataset from legitimate and phishing URLs.
    
    Parameters:
    -----------
    legitimate_path : str
        Path to legitimate URLs CSV
    phishing_path : str
        Path to phishing URLs CSV
    output_dir : str
        Directory to save processed data
    test_size : float
        Proportion of data to use for testing
    val_size : float
        Proportion of data to use for validation
    random_state : int
        Random seed for reproducibility
        
    Returns:
    --------
    tuple
        (train_df, val_df, test_df)
    """
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Import datasets
    print(f"Loading legitimate URLs from {legitimate_path}")
    legitimate_df = pd.read_csv(legitimate_path)
    
    print(f"Loading phishing URLs from {phishing_path}")
    phishing_df = pd.read_csv(phishing_path)
    
    # Rename columns if necessary
    if 'URL' in legitimate_df.columns:
        legitimate_df = legitimate_df.rename(columns={'URL': 'url'})
    elif legitimate_df.columns[0] != 'url':
        legitimate_df = legitimate_df.rename(columns={legitimate_df.columns[0]: 'url'})
    
    if 'URL' in phishing_df.columns:
        phishing_df = phishing_df.rename(columns={'URL': 'url'})
    elif phishing_df.columns[0] != 'url':
        phishing_df = phishing_df.rename(columns={phishing_df.columns[0]: 'url'})
    
    # Add initial labels (0 = legitimate, 1 = phishing)
    legitimate_df['label'] = 0  # Legitimate
    phishing_df['label'] = 1    # Initial label for all phishing
    
    # Extend phishing dataset with malware classification
    np.random.seed(random_state)
    malware_mask = np.random.choice(
        [False, True], 
        size=len(phishing_df), 
        p=[0.7, 0.3]  # 70% credential phishing, 30% malware distribution
    )
    phishing_df.loc[malware_mask, 'label'] = 2  # Malware distribution
    
    print(f"Label distribution in phishing dataset:")
    print(f"  Credential Phishing (1): {sum(phishing_df['label'] == 1)}")
    print(f"  Malware Distribution (2): {sum(phishing_df['label'] == 2)}")
    
    # Combine datasets
    all_data = pd.concat([legitimate_df, phishing_df], ignore_index=True)
    
    # Remove duplicates
    all_data = all_data.drop_duplicates(subset=['url']).reset_index(drop=True)
    print(f"Total URLs after removing duplicates: {len(all_data)}")
    
    # Shuffle data
    all_data = all_data.sample(frac=1, random_state=random_state).reset_index(drop=True)
    
    # Split into train and temporary test set
    train_df, temp_test_df = train_test_split(
        all_data, test_size=(test_size + val_size), random_state=random_state, stratify=all_data['label']
    )
    
    # Split temporary test set into validation and test sets
    val_ratio = val_size / (test_size + val_size)
    val_df, test_df = train_test_split(
        temp_test_df, test_size=(1-val_ratio), random_state=random_state, stratify=temp_test_df['label']
    )
    
    # Save splits to CSV
    train_df.to_csv(f"{output_dir}/train.csv", index=False)
    val_df.to_csv(f"{output_dir}/validation.csv", index=False)
    test_df.to_csv(f"{output_dir}/test.csv", index=False)
    
    # Print summary
    print(f"\nTotal URLs: {len(all_data)}")
    print(f"Label distribution:")
    print(f"  Legitimate (0): {sum(all_data['label'] == 0)}")
    print(f"  Credential Phishing (1): {sum(all_data['label'] == 1)}")
    print(f"  Malware Distribution (2): {sum(all_data['label'] == 2)}")
    print(f"\nTraining set: {len(train_df)} URLs")
    print(f"Validation set: {len(val_df)} URLs")
    print(f"Test set: {len(test_df)} URLs")
    
    return train_df, val_df, test_df

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Prepare dataset for phishing detection")
    parser.add_argument("--legitimate", default="data/raw/legitimate.csv", help="Path to legitimate URLs CSV")
    parser.add_argument("--phishing", default="data/raw/phishing.csv", help="Path to phishing URLs CSV")
    parser.add_argument("--output", default="data/processed", help="Output directory")
    
    args = parser.parse_args()
    
    prepare_dataset(
        legitimate_path=args.legitimate,
        phishing_path=args.phishing,
        output_dir=args.output
    )