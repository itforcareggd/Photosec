from django.contrib import admin
from .models import Photos

class PhotosAdmin(admin.ModelAdmin):
    fields = ['title', 'photo', 'upload_date']
    readonly_fields = ['upload_date']

admin.site.register(Photos, PhotosAdmin)

