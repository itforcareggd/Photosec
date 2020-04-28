import os
from django.conf import settings
from django.http import HttpResponse, HttpResponseNotFound, HttpResponseRedirect, JsonResponse
from django.template import loader
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.urls import reverse
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


@login_required
def qr_code(request):
    token, created = Token.objects.get_or_create(user=request.user)
    if not created:
        token.delete()
        token = Token.objects.create(user=request.user)

    template = loader.get_template('photos/qr_code.html')
    context = {
        "user_id": request.user,
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
                file.delete()
        return HttpResponseRedirect(reverse('file_list'))


class PhotoUploadView(APIView):
    parser_class = (FileUploadParser,)

    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        if 'file' not in request.data:
            raise ParseError('Empty content')

        file = request.data['file']
        title = request.data['title']

        photo = Photos(user=request.user, title=title, photo=file)
        photo.save()

        return HttpResponse('ok')


@login_required
def photos_retrieve(request):
    """
   Send json met photo list on ajax call
    """
    if request.is_ajax():

        photos = Photos.objects.filter(user=request.user)

        if not photos:
            return HttpResponseNotFound('<h1>No photos found</h1>')
        else:
            serializer = PhotoSerializer(photos, many=True)
            return JsonResponse(serializer.data, safe=False)
    else:
        return HttpResponseNotFound('<h1>Not allowed</h1>')


@login_required
def logout_view(request):
    logout(request)
    return HttpResponseRedirect(reverse('login'))
