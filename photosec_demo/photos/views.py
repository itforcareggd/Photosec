import os
from django.conf import settings
from django.http import HttpResponse, HttpResponseNotFound, HttpResponseRedirect, JsonResponse
from django.template import loader
from django.contrib.auth import logout, login
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.urls import reverse
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import ParseError
from rest_framework.parsers import FileUploadParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .models import Photos
from .forms import FilesForm
from .serializers import PhotoSerializer


def create_user(request):
    logout(request)

    if request.method == 'GET':
        template = loader.get_template('photos/create_user.html')
        context = {
        }
        return HttpResponse(template.render(context, request))

    if request.method == 'POST':
        if User.objects.filter(username=request.POST.get('username')).exists():
            template = loader.get_template('photos/create_user.html')
            context = {
               "error" : "username bestaat al"
            }
            return HttpResponse(template.render(context, request))
        else:
            user= User.objects.create(
                username= request.POST.get('username'),
                password= make_password(request.POST.get('password'))
            )
            user.save()
            login(request, user)
            return HttpResponseRedirect(reverse('file_list'))




@login_required
def qr_code(request):
    token, created = Token.objects.get_or_create(user=request.user)
    if not created:
        token.delete()
        token = Token.objects.create(user=request.user)

    template = loader.get_template('photos/qr_code.html')
    context = {
        "user_id": request.user.id,
        "user_token": token.key,
        "app_id": "photosec_app",
    }

    return HttpResponse(template.render(context, request))


@login_required
def file_list(request):
    if request.method == 'GET':
        files_list = Photos.objects.filter(user=request.user)
        template = loader.get_template('photos/files_list.html')
        context = {
            'files_list': files_list
        }
        return HttpResponse(template.render(context, request))

    if request.method == 'POST':
        files_list = Photos.objects.filter(user=request.user)
        for file in files_list:
            if request.POST.get(str(file.id))=='checked':
                path = file.photo.path
                if os.path.isfile(path):
                    os.remove(path)
                    file.delete()
        return HttpResponseRedirect(reverse('file_list'))


class PhotoUploadView(APIView):
    parser_class = (FileUploadParser,)

    def post(self, request, user, token, format=None):
        try:
            token = Token.objects.get(pk=token)
        except ObjectDoesNotExist:
           return Response({'error': 'authentication failure'}, status=401)

        if token.user_id == user:
            if 'file' not in request.data:
                raise ParseError('Empty content')

            file = request.data['file']
            title = request.data['title']

            userId = User.objects.get(pk=user)
            photo = Photos(user=userId, title=title, photo=file)
            photo.save()

            return HttpResponse('ok')
        else:
            return Response({'error': 'authentication failure'}, status=401)


@login_required
def photos_retrieve(request):
    """
   Send json met photo list on ajax call
    """
    if request.is_ajax():

        photos = Photos.objects.filter(user=request.user)

        serializer = PhotoSerializer(photos, many=True)
        return JsonResponse(serializer.data, safe=False)
    else:
        return HttpResponseNotFound('<h1>Not allowed</h1>')


@login_required
def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse('login'))
