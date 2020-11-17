from django.test import TestCase
from django.contrib import auth
from django.contrib.auth import get_user_model


# Create your tests here.
class AuthTestCase(TestCase):
    def setUp(self):
        User = get_user_model()
        self.u = User.objects.create_user('admin@gmail.com',  'pass')
        self.u.is_staff = True
        self.u.is_superuser = True
        self.u.is_active = True
        self.u.save()

    def testLogin(self):
        self.client.login(username='admin@gmail.com', password='pass')