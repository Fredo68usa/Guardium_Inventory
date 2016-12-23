# Guardium_Inventory
By building a normalized inventory of agents and appliances, it is possible to check the consistency of a deployment



IE_DB_2016_2.sql : Creates the schema for a MySQL database
DB_Pop.sql : Populates with test data
Daily_Size_3.py : Python script takes as input the Aggregation Archive Log report and extracts the daily load for each Collector. The output is in csv format and can used in Excel for graphs and other statistics. Guardium V9 only.
