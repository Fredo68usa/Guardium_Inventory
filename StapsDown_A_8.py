import pymongo
import urllib.parse
import json
import getpass
import datetime
import time
import os
import calendar
import socket
import glob
import csv
import psycopg2
import numpy as np
import pandas as pd

myListMeta_IP = []
myListMeta_Env = []
myListMeta_SubEnv = []
myListMeta_FQDN = []
cnt = 0

#Access to PostGreSQL
postgres_connect = None
cursor = None

CURRENT_TIMESTAMP = None


# Opening PostGreSQL
def open_PostGres():

    try:
         postgres_connect = psycopg2.connect(user = "sonargd",
                                  # password = "AIM2020",
                                  # host = "127.0.0.1",
                                  port = "5432",
                                  database = "infra"
                                  )


    except (Exception, psycopg2.Error) as error :
         print("Error while connecting to PostgreSQL", error)
         print ("Hello")

    return(postgres_connect)





# --- Opening Mongo
def open_Mongo():

   # --- Password ----
   try:
        p = getpass.getpass()
   except Exception as error:
        print('ERROR', error)
   else:
        print('Password entered')

   # ----- Connection
   username = urllib.parse.quote_plus('fpetit')
   password = urllib.parse.quote_plus(p)

   myclient = pymongo.MongoClient('mongodb://%s:%s@127.0.0.1:27117/admin' % (username,password))
   return(myclient)

# --- Metadata  ----
def MetaData(myclient,postgres_connect):
    mydb = myclient["sonargd"]
    mycol = mydb["A_IPs"]
    global myListIPs
    myListIPs = pd.DataFrame(list(mycol.find({'Retired' : False, 'Physical Type' : 'Node', 'Server Type' : 'Database'})))
    now = datetime.datetime.now()
    postgres_insert_query = """ INSERT INTO STAP (stapip, stapmetadata, last_update) VALUES (%s,%s,%s) ON CONFLICT (stapip) DO  NOTHING"""
    cnt = 1
    for index, row in myListIPs.iterrows():
      # print ( cnt , ' --' , row['IP'], ' -- ', row['FQDN'])
      cnt = cnt + 1
      record_to_insert = (row['IP'], row['FQDN'] , now )
      cursor.execute(postgres_insert_query, record_to_insert)

    postgres_connect.commit()


if __name__ == '__main__':
    print("Start Detection of STAPs down")
    # print ('Type of myListIPs', type(myListIPs))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  #Create a TCP/IP

    # -- Read list of Crit Servers
    myclient=open_Mongo()
    # -- Open PostGres
    postgres_connect=open_PostGres()
    cursor = postgres_connect.cursor()
    print ( postgres_connect.get_dsn_parameters(),"\n")
    cursor.execute("SELECT version();")
    record = cursor.fetchone()
    print("You are connected to - ", record,"\n")

    # MetaData(myclient,postgres_connect)
    postgres_truncate_query = """ TRUNCATE COLL_STAP"""
    cursor.execute(postgres_truncate_query)
    postgres_connect.commit()
    postgres_truncate_query = """ TRUNCATE STAP CASCADE"""
    cursor.execute(postgres_truncate_query)
    postgres_connect.commit()

    MetaData(myclient,postgres_connect)

    # print (myListIPs)
    # --- Getting STAP infos ----
    mydb = myclient["sonargd"]
    mycol = mydb["stap_status"]

    # date_start = datetime.datetime(2020, 8, 7,19)
    date_start = datetime.datetime.now() - datetime.timedelta(hours=3)
    print (' Start Date : ', date_start )
    # --- Loop for each Critical Server
    # Nbr = mycol.find({'Last Response Received':{'$gte': date_start}}).count()
    Nbr = mycol.find({'Timestamp':{'$gte': date_start}}).count()
    if Nbr == 0 :
       print ('No Records To Process')
       exit(0)
    Docs = pd.DataFrame(list(mycol.find({'Timestamp':{'$gte': date_start}})))
    print ('Nbr of Docs to be processed : ' , Nbr, ' -- ' , len(Docs))
    Docs2 = pd.pivot_table(Docs,values='Last Response Received', index=['TAP IP', 'SonarG Source'], aggfunc=max)
    # Flatenning the Pivot Table .. thx God ...
    Docs2F = pd.DataFrame(Docs2.to_records())
    now = datetime.datetime.now()
    postgres_insert_query = """ INSERT INTO STAP (stapip, stapmetadata, last_update) VALUES (%s,%s,%s) ON CONFLICT (stapip) DO NOTHING"""
    for index, row in Docs2F.iterrows():
           # print ( ' row [0] ' , row[0] )
           # print ( ' ' , row[0] )
           record_to_insert = (row[0],'Not in Inventory', now )
           # print ('Not in Inventory',row[0])
           # print (record_to_insert)
           cursor.execute(postgres_insert_query, record_to_insert)
           data = myListIPs[myListIPs['IP'] == row[0]]
           myListMeta_IP.append(data['IP'].values)
           myListMeta_FQDN.append(data['FQDN'].values)
           myListMeta_Env.append(data['Env'].values)
           myListMeta_SubEnv.append(data['Sub Env'].values)

    postgres_connect.commit()
    # print ('Nbr of Metadata  ', len(myListMeta_IP))
    Docs2F['IP']= myListMeta_IP
    Docs2F['Env']= myListMeta_Env
    Docs2F['Sub Env']= myListMeta_SubEnv
    Docs2F['FQDN']= myListMeta_FQDN

    # print ( '  After  --- \n' , Docs2F.head() )

    # Erase the Table first
    postgres_truncate_query = """ TRUNCATE COLL_STAP"""
    cursor.execute(postgres_truncate_query)
    postgres_connect.commit()
    # Insert latest Coll Stap info
    postgres_insert_query = """ INSERT INTO COLL_STAP (stapip, collip, last_contact) VALUES (%s,%s,%s)"""
    # postgres_insert_query = """ INSERT INTO COLL_STAP (stapip, collip, last_contact, env ) VALUES (%s,%s,%s,%s)"""
    for index, row in Docs2F.iterrows():
        record_to_insert = (row['TAP IP'], row['SonarG Source'], row['Last Response Received'] )
        # print ('row[Env]' , row['Env'], ' -- ', row['TAP IP'] )
        # record_to_insert = (row['TAP IP'], row['SonarG Source'], row['Last Response Received'] , row['Env'])
        cursor.execute(postgres_insert_query, record_to_insert)

    postgres_connect.commit()
    # Check for known missing STAP in STAP Status
    # print (' Type of myListIPs  ', type(myListIPs) , ' -- ', len(myListIPs))
    # print (myListIPs)
    for index, row in myListIPs.iterrows():
        cnt = cnt + 1
        # print('Ref IP' , row['IP'], ' -- ' , cnt )
        data = Docs2F[Docs2F['TAP IP'] == row['IP']]
        if data.empty :
           print ('STAP no Status', row['IP'],' -- ' , row['FQDN'])

    if(postgres_connect):
      cursor.close()
      postgres_connect.close()
      print("PostgreSQL connection is closed")


    print("End Detection of STAPs down")
