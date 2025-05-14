import json
from urllib.parse import unquote_plus
import boto3
from botocore.exceptions import ClientError
import os
import logging

print('Chargement de la fonction')
logger = logging.getLogger()
logger.setLevel("INFO")

s3_client = boto3.client('s3')
rekognition = boto3.client('rekognition')

dynamodb_resource = None
table = None

table_name = os.getenv("table")  # Correction de la variable d'environnement

if table_name:
    try:
        dynamodb_resource = boto3.resource('dynamodb')
        table = dynamodb_resource.Table(table_name)
        logger.info(f"Table DynamoDB initialisée avec succès pour la table : {table_name}")
    except Exception as e:
        logger.error(f"Échec de l'initialisation de la ressource DynamoDB pour le nom de la table '{table_name}': {e}", exc_info=True)
else:
    logger.error("La variable d'environnement table n'est pas définie !")  # Correction du nom de la variable d'environnement

def lambda_handler(event, context):
    """
    Fonction Lambda déclenchée par les événements S3 pour traiter les images téléchargées,
    analyser les étiquettes à l'aide d'Amazon Rekognition et mettre à jour une table DynamoDB.
    """
    if not table:
        logger.error("La ressource de la table DynamoDB n'est pas initialisée. Abandon.")
        return {'statusCode': 500, 'body': json.dumps('Erreur interne du serveur : Table non configurée ou échec de l\'initialisation')}

    for record in event.get("Records", []):
        try:
            s3_data = record.get("s3", {})
            bucket_name = s3_data.get("bucket", {}).get("name")
            object_key = s3_data.get("object", {}).get("key")

            if not bucket_name or not object_key:
                logger.warning(f"Enregistrement ignoré en raison de l'absence du nom du bucket ou de la clé de l'objet : {record}")
                continue

            key = unquote_plus(object_key)
            logger.info(f"Traitement de l'objet s3://{bucket_name}/{key}")

            parts = key.split('/')
            if len(parts) < 3:
                logger.error(f"Format de clé invalide : '{key}'. Format attendu : 'user/post_id/filename'. Ignoré.")
                continue

            user = parts[0]
            post_id = parts[1]

            logger.info(f"Extrait de la clé : user='{user}', post_id='{post_id}'")

            logger.info(f"Appel à Rekognition pour bucket='{bucket_name}', clé='{key}'")
            try:
                label_data = rekognition.detect_labels(
                    Image={"S3Object": {
                        "Bucket": bucket_name,
                        "Name": key
                        }
                    },
                    MaxLabels=5,
                    MinConfidence=75
                )
                logger.debug(f"Réponse brute de Rekognition : {label_data.keys()}")
            except ClientError as e:
                logger.error(f"Erreur Client Rekognition pour la clé '{key}' : {e}", exc_info=True)
                continue
            except Exception as e:
                logger.error(f"Erreur inattendue lors de l'appel à Rekognition pour la clé '{key}' : {e}", exc_info=True)
                continue

            labels = [label["Name"] for label in label_data.get("Labels", [])]
            logger.info(f"Étiquettes détectées : {labels}")

            logger.info(f"Tentative de mise à jour de l'élément DynamoDB avec la clé : post_id='{post_id}'") # Modification de la clé pour correspondre à la table
            try:
                update_response = table.update_item(
                    Key={
                        'post_id': post_id  # Utilisation de post_id comme clé primaire
                    },
                    UpdateExpression="SET labels = :lbl", # Suppression de la mise à jour de l'image
                    ExpressionAttributeValues={
                        ':lbl': labels
                    },
                    ReturnValues="UPDATED_NEW"
                )
                logger.info(f"Mise à jour DynamoDB réussie pour le post '{post_id}'. Attributs mis à jour : {update_response.get('Attributes')}")

            except ClientError as e:
                if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
                    logger.error(f"Mise à jour DynamoDB échouée pour le post '{post_id}' : L'élément n'existe pas ou la condition a échoué.", exc_info=True)
                else:
                    logger.error(f"Erreur Client DynamoDB lors de la mise à jour du post '{post_id}' : {e}", exc_info=True)
                continue
            except Exception as e:
                logger.error(f"Erreur inattendue lors de la mise à jour de DynamoDB pour le post '{post_id}' : {e}", exc_info=True)
                continue

        except Exception as e:
            logger.error(f"Erreur lors du traitement de l'enregistrement : {record}. Erreur : {e}", exc_info=True)
            continue

    return {
        'statusCode': 200,
        'body': json.dumps('Traitement des événements S3 terminé.')
    }
