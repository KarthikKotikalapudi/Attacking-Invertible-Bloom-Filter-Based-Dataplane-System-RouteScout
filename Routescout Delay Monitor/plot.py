import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Load data from CSV file
file_path = './tx_output/baseline.csv'  # Update the path to your CSV file
data = pd.read_csv(file_path)

# Display the first few rows of the dataframe

# Ensure the 'unExtractable Flows' column is treated as integers if not already
data['Non-Extractable'] = data['Non-Extractable'].astype(int)

# Sorting the data
# sorted_flows = np.sort(data['Non-Extractable'])

# Calculate CDF
# cdf = np.arange(1, len(sorted_flows)+1) / len(sorted_flows)

# Plotting the CDF
plt.figure(figsize=(8, 5))
plt.plot(data['Non-Extractable'], marker='.')
plt.title('CDF of unExtractable Flows vs. Percentage of Epochs')
plt.xlabel('Number of unExtractable Flows')
plt.ylabel('Percentage of Epochs')
plt.grid(True)
plt.show()

