#################################################################################################
##                                                                                             ##
##                                 NE PAS TOUCHER CETTE PARTIE                                 ##
##                                                                                             ##
## 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 ##
import boto3
from botocore.config import Config
import os
import uuid
from dotenv import load_dotenv
from typing import Union
import logging
from fastapi import FastAPI, Request, status, Header
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from getSignedUrl import getSignedUrl

load_dotenv()

app = FastAPI()
logger = logging.getLogger("uvicorn")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
	exc_str = f'{exc}'.replace('\n', ' ').replace('   ', ' ')
	logger.error(f"{request}: {exc_str}")
	content = {'status_code': 10422, 'message': exc_str, 'data': None}
	return JSONResponse(content=content, status_code=status.HTTP_422_UNPROCESSABLE_ENTITY)


class Post(BaseModel):
    title: str
    body: str

my_config = Config(
    region_name='us-east-1',
    signature_version='v4',
)

dynamodb = boto3.resource('dynamodb', config=my_config)
table = dynamodb.Table(os.getenv("DYNAMO_TABLE"))
s3_client = boto3.client('s3', config=boto3.session.Config(signature_version='s3v4'))
bucket = os.getenv("BUCKET")

## ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ##
##                                                                                                ##
####################################################################################################

def create_presigned_url(bucket_name, object_name, expiration=3600):
    """Générer une URL présignée pour S3"""
    if not s3_client or not bucket_name or not object_name:
        logger.warning(f"URL présignée non générée pour {object_name} : client, nom de bucket ou clé manquant.")
        return None

    try:
        response = s3_client.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': object_name},
            ExpiresIn=expiration
        )
        logger.debug(f"URL présignée générée pour {object_name}")
        return response
    except ClientError as e:
        logger.error(f"Erreur Client S3 lors de la génération de l'URL présignée pour {object_name} : {e}", exc_info=True)
        return None
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la génération de l'URL présignée pour {object_name} : {e}", exc_info=True)
        return None



@app.post("/posts", status_code=status.HTTP_201_CREATED)
async def post_a_post(post: Post, authorization: str | None = Header(default=None)):

    user = authorization
    post_id = str(uuid.uuid4())

    logger.info(f"Création d'un post pour l'utilisateur : {user}, ID du post : {post_id}")
    logger.info(f"Titre : {post.title}, Contenu : {post.body}")

    item = {
        'user': user,
        'id': post_id,
        'title': post.title,
        'body': post.body,
        'image': None,
        'labels': []
    }
    try:
        res = table.put_item(Item=item)
        logger.info(f"put_item DynamoDB réussi. Métadonnées : {res.get('ResponseMetadata')}")
        return item
    except ClientError as e:
        logger.error(f"Erreur Client DynamoDB lors de put_item : {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"message": f"Échec de la création du post : {e.response['Error']['Message']}"})
    except Exception as e:
        logger.error(f"Erreur inattendue lors de put_item : {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"message": "Erreur interne lors de la création du post"})


@app.get("/posts")
async def get_all_posts(user: Union[str, None] = None):
    """Récupère les posts SANS utiliser de préfixes pour la query."""
    logger.info(f"--- GET /posts --- Requête reçue avec le paramètre utilisateur : '{user}'")

    items = []
    try:
        if user:
            logger.info(f"Tentative de requête DynamoDB pour l'utilisateur : '{user}'")
            response = table.query(
                KeyConditionExpression=Key('user').eq(user)
            )
            items = response.get('Items', [])
            logger.info(f"La requête DynamoDB a retourné {len(items)} éléments.")
        else:
            logger.warning("Tentative de scan DynamoDB pour tous les utilisateurs (aucun paramètre utilisateur fourni)")
            response = table.scan()
            items = response.get('Items', [])
            while 'LastEvaluatedKey' in response:
                logger.debug(f"Scan de la page suivante... (total actuel : {len(items)} éléments)")
                response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
                items.extend(response.get('Items', []))
            logger.info(f"Le scan DynamoDB a retourné {len(items)} éléments au total.")

    except ClientError as e:
        logger.error(f"Erreur Client DynamoDB lors de l'accès à la table : {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"message": f"Erreur base de données : {e.response['Error']['Message']}"})
    except Exception as e:
        logger.error(f"!!! ERREUR INATTENDUE lors de l'accès à DynamoDB : {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"message": "Erreur interne lors de la récupération des données"})

    logger.info(f"Traitement de {len(items)} éléments pour la réponse...")
    res = []
    for item in items:
        p_item = dict(item)

        image_key = p_item.get('image')
        p_item['image_url'] = None
        if image_key and bucket and s3_client:
            p_item['image_url'] = create_presigned_url(bucket, image_key)
            if not p_item['image_url']:
                logger.warning(f"Échec de la génération de l'URL présignée pour la clé : {image_key}")
        elif image_key:
            logger.warning(f"Impossible de générer une URL présignée pour {image_key}, bucket ou client S3 non configuré.")

        p_item['image_s3_key'] = p_item.pop('image', None)

        raw_labels = p_item.get('labels', [])
        simple_labels: List[str] = []
        if isinstance(raw_labels, list):
            for label_obj in raw_labels:
                if isinstance(label_obj, dict) and 'S' in label_obj:
                    simple_labels.append(label_obj['S'])
                elif isinstance(label_obj, str):
                    simple_labels.append(label_obj)
                else:
                    logger.warning(f"L'élément ID {p_item.get('id', 'N/A')} contient un format de label inattendu : {label_obj}")
        else:
            logger.warning(f"L'élément ID {p_item.get('id', 'N/A')} a un format de labels non-list : {raw_labels}")
        p_item['labels'] = simple_labels

        res.append(p_item)

    return res
    
@app.delete("/posts/{post_id}")
async def delete_post(post_id: str, authorization: str | None = Header(default=None)):
    user = authorization

    logger.info(f"Tentative de suppression du post pour l'utilisateur : {user}, ID du post : {post_id}")

    try:
        get_response = table.get_item(
            Key={'user': user, 'id': post_id}
        )
        item_to_delete = get_response.get('Item')

        if not item_to_delete:
            logger.warning(f"Échec de la suppression : post introuvable pour user='{user}', post_id='{post_id}'")
            return JSONResponse(status_code=404, content={"message": "Post introuvable"})

        image_s3_key = item_to_delete.get('image')
        if image_s3_key:
            logger.info(f"Suppression de l'image associée dans le bucket S3 '{bucket}' : {image_s3_key}")
            try:
                s3_client.delete_object(Bucket=bucket, Key=image_s3_key)
                logger.info(f"Suppression réussie de l'objet S3 : {image_s3_key}")
            except ClientError as e:
                logger.error(f"Erreur Client S3 lors de la suppression de l'objet {image_s3_key} : {e}", exc_info=True)
            except Exception as e:
                logger.error(f"Erreur inattendue lors de la suppression de l'objet {image_s3_key} dans S3 : {e}", exc_info=True)

        delete_response = table.delete_item(
            Key={'user': user, 'id': post_id},
            ReturnValues='ALL_OLD'
        )
        logger.info(f"Suppression réussie dans DynamoDB. Métadonnées : {delete_response.get('ResponseMetadata')}")
        item = dict(delete_response.get('Attributes', {}))
        return item

    except ClientError as e:
        logger.error(f"Erreur Client DynamoDB lors de l'opération de suppression pour {post_id} : {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"message": f"Échec de la suppression du post : {e.response['Error']['Message']}"})
    except Exception as e:
        logger.error(f"Erreur inattendue lors de la suppression du post {post_id} : {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"message": "Erreur interne lors de la suppression du post"})



#################################################################################################
##                                                                                             ##
##                                 NE PAS TOUCHER CETTE PARTIE                                 ##
##                                                                                             ##
## 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 👇 ##
@app.get("/signedUrlPut")
async def get_signed_url_put(filename: str,filetype: str, postId: str,authorization: str | None = Header(default=None)):
    return getSignedUrl(filename, filetype, postId, authorization)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="debug")

## ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️ ☝️  ##
##                                                                                              ##
##################################################################################################