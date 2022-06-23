from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from authentification.utils import generate_token


#classe de test de basse  creee la methode de configuration de test
class BaseTest(TestCase):
    def setUp(self):
        self.register_url=reverse('register')
        self.login_url=reverse('login')
        #pour test l'inscription du user
        self.user={
            'email':'testemail@gmail.com',
            'username':'username',
            'password':'password',
            'password2':'password',
            'name':'fullname'
        }
        self.user_short_password={
            'email':'testemail@gmail.com',
            'username':'username',
            'password':'tes',
            'password2':'tes',
            'name':'fullname'
        }
        self.user_unmatching_password={

            'email':'testemail@gmail.com',
            'username':'username',
            'password':'teslatt',
            'password2':'teslatto',
            'name':'fullname'
        }

        self.user_invalid_email={
            
            'email':'test.com',
            'username':'username',
            'password':'teslatt',
            'password2':'teslatto',
            'name':'fullname'
        }
        return super().setUp()

#on test l'inscritpion ici
#d'abord est le user peut voir la page avec la fonction assertEqual 
#ensuite on test le templates
class RegisterTest(BaseTest):
#test de la page
   def test_can_view_page_correctement(self):
       response=self.client.get(self.register_url)
       self.assertEqual(response.status_code,200)
       self.assertTemplateUsed(response,'auth/register.html')
# test de l'inscription
   def test_can_register_user(self):
        response=self.client.post(self.register_url,self.user,format='text/html')
        self.assertEqual(response.status_code,302)
# ici on test si le mot passe corresponda au critere
   def test_cant_register_user_withshortpassword(self):
        response=self.client.post(self.register_url,self.user_short_password,format='text/html')
        self.assertEqual(response.status_code,400)
# on test si les mot de passe correspond
   def test_cant_register_user_with_unmatching_passwords(self):
        response=self.client.post(self.register_url,self.user_unmatching_password,format='text/html')
        self.assertEqual(response.status_code,400)
        #ici on test si l'email est invalide
   def test_cant_register_user_with_invalid_email(self):
        response=self.client.post(self.register_url,self.user_invalid_email,format='text/html')
        self.assertEqual(response.status_code,400)

   def test_cant_register_user_with_taken_email(self):
        self.client.post(self.register_url,self.user,format='text/html')
        response=self.client.post(self.register_url,self.user,format='text/html')
        self.assertEqual(response.status_code,400)

class LoginTest(BaseTest):
    #on test si la page peut etre acceder
    def test_can_access_page(self):
        response=self.client.get(self.login_url)
        self.assertEqual(response.status_code,200)
        self.assertTemplateUsed(response,'auth/login.html')
        #on test si la connexion passe
    def test_login_success(self):
        #on cree un user puis on l'active
        self.client.post(self.register_url,self.user,format='text/html')
        user=User.objects.filter(email=self.user['email']).first()
        user.is_active=True
        user.save()
        #ici on login le user
        response= self.client.post(self.login_url,self.user,format='text/html')
        self.assertEqual(response.status_code,302)
    #ici on creer le user sans verifier l'email
    def test_cantlogin_with_unverified_email(self):
        self.client.post(self.register_url,self.user,format='text/html')
        response= self.client.post(self.login_url,self.user,format='text/html')
        self.assertEqual(response.status_code,302)
#le user sans nom utilisateur
    def test_cantlogin_with_no_username(self):
        response= self.client.post(self.login_url,{'password':'passwped','username':''},format='text/html')
        self.assertEqual(response.status_code,401)
        #le user sans MP
    def test_cantlogin_with_no_password(self):
        response= self.client.post(self.login_url,{'username':'passwped','password':''},format='text/html')
        self.assertEqual(response.status_code,401)

class UserVerifyTest(BaseTest):
    def test_user_ctivates_success(self):
        user=User.objects.create_user('testuser','crytest@gmail.com')
        user.set_password('tetetebvghhhhj')
        user.is_active=False
        user.save()
        uid=urlsafe_base64_encode(force_bytes(user.pk))
        token=generate_token.make_token(user)
        response=self.client.get(reverse('activate',kwargs={'uidb64':uid,'token':token}))
        self.assertEqual(response.status_code,302)
        user=User.objects.get(email='crytest@gmail.com')
        self.assertTrue(user.is_active)
    def test_user_cant_ctivates_succesfully(self):
        user=User.objects.create_user('testuser','crytest@gmail.com')
        user.set_password('tetetebvghhhhj')
        user.is_active=False
        user.save()
        uid=urlsafe_base64_encode(force_bytes(user.pk))
        token=generate_token.make_token(user)
        response=self.client.get(reverse('activate',kwargs={'uidb64':'uid','token':'token'}))
        self.assertEqual(response.status_code,401)
        user=User.objects.get(email='crytest@gmail.com')
        self.assertFalse(user.is_active)